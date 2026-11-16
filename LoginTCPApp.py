import base64
import random
import socket
import struct
import time
import traceback
from urllib.parse import urlparse
import hashlib
import binascii
import os
import re
import uuid
import requests
import socks
from flask import Flask, request, jsonify


class BaseProtobufDecoder:
    TAG_TO_FIELD = {
        1: "version",
        2: "id",
        3: "command_type",
        4: "command",
        5: "result",
        6: "timestamp",
        7: "fragment_number",
        8: "fragment_index"
    }

    def parse_varint(self, data, offset):
        shift = 0
        result = 0
        while True:
            if offset >= len(data):
                raise Exception("Unexpected end of data while parsing varint")
            b = data[offset]
            result |= (b & 0x7F) << shift
            offset += 1
            if not (b & 0x80):
                break
            shift += 7
        return result, offset

    def parse_length_delimited(self, data, offset):
        length, offset = self.parse_varint(data, offset)
        value = data[offset:offset + length]
        offset += length
        return value, offset

    def parse_fixed64(self, data, offset):
        value = data[offset:offset + 8]
        offset += 8
        return value, offset

    def parse_fixed32(self, data, offset):
        value = data[offset:offset + 4]
        offset += 4
        return value, offset

    def decode_fields(self, protobuf_data):
        offset = 0
        fields = {}
        while offset < len(protobuf_data):
            key, offset = self.parse_varint(protobuf_data, offset)
            tag = key >> 3
            wire_type = key & 0x07
            if wire_type == 0:
                value, offset = self.parse_varint(protobuf_data, offset)
            elif wire_type == 1:
                value, offset = self.parse_fixed64(protobuf_data, offset)
            elif wire_type == 2:
                value, offset = self.parse_length_delimited(
                    protobuf_data, offset)
            elif wire_type == 5:
                value, offset = self.parse_fixed32(protobuf_data, offset)
            else:
                raise Exception(
                    f"Unsupported wire type: {wire_type} for tag: {tag}")
            fields[tag] = (wire_type, value)
        return fields

    def decode_client_packet_header(self, header_bytes):
        fields = self.decode_fields(header_bytes)
        header = {}
        for tag, (wire_type, value) in fields.items():
            field_name = self.TAG_TO_FIELD.get(tag, f"unknown_field_{tag}")
            if wire_type == 0:
                header[field_name] = value
            elif wire_type in (1, 5):
                header[field_name] = int.from_bytes(value, byteorder='little')
            elif wire_type == 2:
                header[field_name] = value.hex()
            else:
                header[field_name] = value
        return header


class PacketSend(BaseProtobufDecoder):
    def encode_varint(self, value):
        buf = bytearray()
        while True:
            to_write = value & 0x7F
            value >>= 7
            if value:
                buf.append(to_write | 0x80)
            else:
                buf.append(to_write)
                break
        return bytes(buf)

    def build_packet(self, header_bytes, body_bytes=None):
        if body_bytes is None:
            body_bytes = b""
        header_length = len(header_bytes)
        payload = header_length.to_bytes(
            2, byteorder='big') + header_bytes + body_bytes
        framing = len(payload).to_bytes(4, byteorder='little')
        return framing + payload


MASK32 = 0xffffffff


class Lrand48:
    def __init__(self, seed):
        self.a = 0x5DEECE66D
        self.c = 0xB
        self.m = 1 << 48
        self.state = ((seed & 0xffffffff) << 16) | 0x330E

    def lrand48(self):
        self.state = (self.state * self.a + self.c) & (self.m - 1)
        return self.state >> 17


class XTEACBC:
    BLOCK_SIZE = 8
    DELTA = 1640531527

    def __init__(self, key_bytes: bytes, endian: str = 'little'):
        if len(key_bytes) != 16:
            raise ValueError("Key must be 16 bytes!")
        self.key = self._prepare_key(key_bytes, endian)
        self.key_bytes = key_bytes
        self.endian = endian

    @staticmethod
    def _prepare_key(key_bytes: bytes, endian: str = 'little'):
        return [int.from_bytes(key_bytes[i*4:(i+1)*4], endian) for i in range(4)]

    @staticmethod
    def _add32(a, b):
        return (a + b) & MASK32

    @staticmethod
    def _sub32(a, b):
        return (a - b) & MASK32

    @staticmethod
    def _xtea_decrypt_block_custom(v0: int, v1: int, key: list, rounds: int = 32, c: int = 1640531527):
        s = (-957401312) & MASK32
        for _ in range(rounds):
            t = (v0 + ((16 * v0) ^ (v0 >> 5))) & MASK32
            idx0 = ((s >> 9) & 0xC) >> 2
            part0 = (s + key[idx0]) & MASK32
            v1 = XTEACBC._sub32(v1, t ^ part0)
            t2 = (v1 + ((16 * v1) ^ (v1 >> 5))) & MASK32
            idx1 = (((s & 0xff) + 71) & 3)
            part1 = (s + key[idx1] + c) & MASK32
            v0 = XTEACBC._sub32(v0, t2 ^ part1)
            s = XTEACBC._add32(s, c)
        return v0, v1

    @staticmethod
    def _bytes_to_block(b: bytes):
        if len(b) != 8:
            raise ValueError("Block must be 8 bytes!")
        w0 = int.from_bytes(b[0:4], 'little')
        w1 = int.from_bytes(b[4:8], 'little')
        return (w0, w1)

    @staticmethod
    def remove_padding(data: bytes, block_size: int = 8):
        if not data:
            raise ValueError("Data is empty!")
        pad = data[-1]
        if pad < 1 or pad > block_size:
            raise ValueError(f"Invalid padding value: {pad}")
        if data[-pad:] != bytes([pad] * pad):
            raise ValueError("Invalid padding!")
        return data[:-pad]

    def crypt_xtea_cbc_decrypt(self, ciphertext: bytes, endian='little') -> bytes:
        if len(ciphertext) % self.BLOCK_SIZE != 0 or len(ciphertext) < self.BLOCK_SIZE:
            raise ValueError("Ciphertext length invalid!")
        nblocks = len(ciphertext) // self.BLOCK_SIZE
        blocks = [self._bytes_to_block(
            ciphertext[i * self.BLOCK_SIZE:(i + 1) * self.BLOCK_SIZE]) for i in range(nblocks)]
        iv = blocks[0]
        decrypted = b""
        prev = iv
        for block in blocks[1:]:
            v0, v1 = block
            d0, d1 = self._xtea_decrypt_block_custom(
                v0, v1, self.key, rounds=32, c=self.DELTA)
            prev0, prev1 = prev
            p0 = d0 ^ prev0
            p1 = d1 ^ prev1
            decrypted += p0.to_bytes(4, 'little') + p1.to_bytes(4, 'little')
            prev = block
        output_len = len(ciphertext) - 16
        raw = decrypted[:output_len]
        return self.remove_padding(raw, self.BLOCK_SIZE)

    def crypt_xtea_cbc_encrypt(self, plaintext: bytes, iv: bytes = None) -> bytes:
        v46 = len(plaintext)
        full_blocks = v46 >> 3
        v52 = 8 * full_blocks
        v48 = full_blocks
        out_size = v52 + 24
        out_dwords = [0] * (out_size // 4)
        if iv is not None:
            if len(iv) != 8:
                raise ValueError("IV phải có độ dài 8 byte")
            v4 = int.from_bytes(iv[0:4], 'little')
            v5 = int.from_bytes(iv[4:8], 'little')
            v6 = v4 | (v5 >> 31)
        else:
            rng = Lrand48(int(time.time()))
            v4 = rng.lrand48() & 0xffffffff
            v5 = rng.lrand48() & 0xffffffff
            v6 = v4 | (v5 >> 31)
        v8 = 0
        delta = 0x61C88647
        rounds = 32
        v49 = v6
        v50 = v5
        for _ in range(rounds):
            temp1 = (v6 + ((16 * v6) ^ (v6 >> 5))) & 0xffffffff
            k1 = int.from_bytes(
                self.key_bytes[((v8 & 3) * 4):((v8 & 3) * 4 + 4)], 'little')
            temp2 = (v8 + k1) & 0xffffffff
            v5 = (v5 + (temp1 ^ temp2)) & 0xffffffff
            temp1 = (v5 + ((16 * v5) ^ (v5 >> 5))) & 0xffffffff
            second_index = (((v8 - delta) >> 9) & 0xC) >> 2
            k2 = int.from_bytes(
                self.key_bytes[(second_index * 4):(second_index * 4 + 4)], 'little')
            temp2 = (v8 + k2) & 0xffffffff
            temp2 = (temp2 - delta) & 0xffffffff
            v6 = (v6 + (temp1 ^ temp2)) & 0xffffffff
            v8 = (v8 - delta) & 0xffffffff
        out_dwords[0] = v5
        out_dwords[1] = v6
        pos = 0
        out_index = 2
        for i in range(v48):
            p0 = int.from_bytes(plaintext[pos:pos+4], 'little')
            p1 = int.from_bytes(plaintext[pos+4:pos+8], 'little')
            pos += 8
            combined = ((p1 & 0xffffffff) << 32) | (p0 & 0xffffffff)
            old_pair = ((v49 & 0xffffffff) << 32) | (v50 & 0xffffffff)
            total = (combined + old_pair) & 0xffffffffffffffff
            v49 = (total >> 32) & 0xffffffff
            v50 = (v50 + p0) & 0xffffffff
            v6 = v6 ^ p1
            v16 = p0 ^ v5
            v17 = 0
            for j in range(32):
                temp1 = (v6 + ((16 * v6) ^ (v6 >> 5))) & 0xffffffff
                k1 = int.from_bytes(
                    self.key_bytes[((v17 & 3) * 4):((v17 & 3) * 4 + 4)], 'little')
                temp2 = (v17 + k1) & 0xffffffff
                v16 = (v16 + (temp1 ^ temp2)) & 0xffffffff
                temp1 = (v16 + ((16 * v16) ^ (v16 >> 5))) & 0xffffffff
                second_index = (((v17 - delta) >> 9) & 0xC) >> 2
                k2 = int.from_bytes(
                    self.key_bytes[(second_index * 4):(second_index * 4 + 4)], 'little')
                temp2 = (v17 + k2) & 0xffffffff
                temp2 = (temp2 - delta) & 0xffffffff
                v6 = (v6 + (temp1 ^ temp2)) & 0xffffffff
                v17 = (v17 - delta) & 0xffffffff
            v5 = v16
            out_dwords[out_index] = v16
            out_dwords[out_index + 1] = v6
            out_index += 2
            remainder = v46 & 7
            if remainder > 0:
                leftover = plaintext[pos:pos+remainder]
            else:
                leftover = b""
        tmp = self.custom_pad_c_style(leftover)
        v53 = int.from_bytes(tmp, 'little')
        v26 = (v53 & 0xffffffff) ^ v5
        v27 = ((v53 >> 32) & 0xffffffff) ^ v6
        v28 = 0
        for i in range(32):
            temp1 = (v27 + ((16 * v27) ^ (v27 >> 5))) & 0xffffffff
            k1 = int.from_bytes(
                self.key_bytes[((v28 & 3) * 4):((v28 & 3) * 4 + 4)], 'little')
            temp2 = (v28 + k1) & 0xffffffff
            v26 = (v26 + (temp1 ^ temp2)) & 0xffffffff
            temp1 = (v26 + ((16 * v26) ^ (v26 >> 5))) & 0xffffffff
            second_index = (((v28 - delta) >> 9) & 0xC) >> 2
            k2 = int.from_bytes(
                self.key_bytes[(second_index * 4):(second_index * 4 + 4)], 'little')
            temp2 = (v28 + k2) & 0xffffffff
            temp2 = (temp2 - delta) & 0xffffffff
            v27 = (v27 + (temp1 ^ temp2)) & 0xffffffff
            v28 = (v28 - delta) & 0xffffffff
        out_dwords[out_index] = v26
        out_dwords[out_index + 1] = v27
        out_index += 2
        combined_pair = ((v49 & 0xffffffff) << 32) | (v50 & 0xffffffff)
        total_64 = (combined_pair + v53) & 0xffffffffffffffff
        v30 = (total_64 >> 32) & 0xffffffff
        v31 = (v50 + (v53 & 0xffffffff)) & 0xffffffff
        v32 = v26 ^ v31
        v33 = v27 ^ v30
        v34 = 0
        for i in range(32):
            temp1 = (v33 + ((16 * v33) ^ (v33 >> 5))) & 0xffffffff
            k1 = int.from_bytes(
                self.key_bytes[((v34 & 3) * 4):((v34 & 3) * 4 + 4)], 'little')
            temp2 = (v34 + k1) & 0xffffffff
            v32 = (v32 + (temp1 ^ temp2)) & 0xffffffff
            temp1 = (v32 + ((16 * v32) ^ (v32 >> 5))) & 0xffffffff
            second_index = (((v34 - delta) >> 9) & 0xC) >> 2
            k2 = int.from_bytes(
                self.key_bytes[(second_index * 4):(second_index * 4 + 4)], 'little')
            temp2 = (v34 + k2) & 0xffffffff
            temp2 = (temp2 - delta) & 0xffffffff
            v33 = (v33 + (temp1 ^ temp2)) & 0xffffffff
            v34 = (v34 - delta) & 0xffffffff
        out_dwords[out_index] = v32
        out_dwords[out_index + 1] = v33
        out_index += 2
        result = b"".join(dw.to_bytes(4, 'little') for dw in out_dwords)
        return result

    def custom_pad_c_style(self, plaintext: bytes) -> bytes:
        length = len(plaintext)
        rem = length & 7
        padded_block = bytearray(8)
        if rem != 0:
            padded_block[:rem] = plaintext[-rem:]
        pad_val = 8 - rem
        for i in range(pad_val):
            padded_block[rem + i] = pad_val
        return padded_block


class ProtoUtils:
    @staticmethod
    def encode_varint(value):
        result = bytearray()
        while True:
            to_write = value & 0x7F
            value >>= 7
            if value:
                result.append(to_write | 0x80)
            else:
                result.append(to_write)
                break
        return bytes(result)

    @classmethod
    def encode_length_delimited(cls, data_bytes):
        return cls.encode_varint(len(data_bytes)) + data_bytes


class BaseLoginRequest:
    def __init__(self):
        self.random_key = os.urandom(16)
        self.timestamp = int(time.time())

    def build_header(self, type_field):
        header_fields = {
            1: 285212918,
            2: hash(uuid.getnode()),
            3: 2,
            4: type_field,
            6: int(time.time()),
        }
        message = b""
        for tag, value in header_fields.items():
            key = ProtoUtils.encode_varint((tag << 3) | 0)
            message += key + ProtoUtils.encode_varint(value)
        return message

    def encrypt_data(self, data_bytes):
        xtea = XTEACBC(self.random_key)
        return xtea.crypt_xtea_cbc_encrypt(data_bytes)

    def build_encrypted_body(self, key_bytes, data_bytes, key_tag=1, data_tag=2):
        message = b""
        message += ProtoUtils.encode_varint((key_tag << 3) | 2) + \
            ProtoUtils.encode_length_delimited(key_bytes)
        message += ProtoUtils.encode_varint((data_tag << 3) | 2) + \
            ProtoUtils.encode_length_delimited(data_bytes)
        return message

    def build_full_packet(self, request_data_builder, header_type):
        data_bytes = request_data_builder()
        ciphertext = self.encrypt_data(data_bytes)
        body = self.build_encrypted_body(self.random_key, ciphertext)
        header = self.build_header(header_type)
        ps = PacketSend()
        return ps.build_packet(header, body)


class LoginPrepareRequest(BaseLoginRequest):
    def __init__(self, account):
        super().__init__()
        self.account = account
        self.auth_type = 0
        self.account_type = 2 if re.match(
            r"[^@]+@[^@]+\.[^@]+", account) else 1
        self.client_type = 4352
        self.client_version = 246

    def build_request_data(self):
        message = b""
        message += ProtoUtils.encode_varint((1 << 3) | 0) + \
            ProtoUtils.encode_varint(self.auth_type)
        message += ProtoUtils.encode_varint((2 << 3) | 0) + \
            ProtoUtils.encode_varint(self.account_type)

        account_bytes = self.account.encode('utf-8')
        message += ProtoUtils.encode_varint((3 << 3) | 2) + \
            ProtoUtils.encode_length_delimited(account_bytes)

        message += ProtoUtils.encode_varint((4 << 3) | 0) + \
            ProtoUtils.encode_varint(self.client_type)
        message += ProtoUtils.encode_varint((5 << 3) | 0) + \
            ProtoUtils.encode_varint(self.client_version)
        return message

    def build_full_packet(self):
        return super().build_full_packet(self.build_request_data, header_type=256)


class LoginRequestHandler(BaseLoginRequest):
    def __init__(self, password=None, key=None):
        self.random_key = bytes.fromhex(key)
        self.device_id = str(hash(uuid.getnode())).encode('utf-8')
        self.login_mode = 0
        self.password_hash = hashlib.md5(password.encode(
            'utf-8')).hexdigest().encode('utf-8') if password else None
        self.user_status = 4608
        self.timestamp = int(time.time())

    def build_request_data(self):
        message = b""
        message += ProtoUtils.encode_varint((1 << 3) | 2) + \
            ProtoUtils.encode_length_delimited(self.password_hash)
        message += ProtoUtils.encode_varint((2 << 3) | 0) + \
            ProtoUtils.encode_varint(self.login_mode)
        user_status_msg = self.build_user_status_message()
        message += ProtoUtils.encode_varint((3 << 3) | 2) + \
            ProtoUtils.encode_length_delimited(user_status_msg)
        message += ProtoUtils.encode_varint((4 << 3) | 2) + \
            ProtoUtils.encode_length_delimited(self.device_id)
        return message

    def build_user_status_message(self):
        message = b""
        message += ProtoUtils.encode_varint((2 << 3) | 0) + \
            ProtoUtils.encode_varint(self.user_status)
        return message

    def build_full_packet(self):
        data_bytes = self.build_request_data()
        ciphertext = self.encrypt_data(data_bytes)
        header = self.build_header(257)
        body = ProtoUtils.encode_varint(
            (1 << 3) | 2) + ProtoUtils.encode_length_delimited(ciphertext)
        ps = PacketSend()
        return ps.build_packet(header, body)


class EmptyPacket(BaseLoginRequest):
    def __init__(self, encryption_key, command):
        super().__init__()
        self.encryption_key = bytes.fromhex(encryption_key)
        self.command = command

    def build_request_data(self):
        return b""

    def build_full_packet(self):
        header = self.build_header(self.command)
        header_length = len(header)
        header_length_bytes = header_length.to_bytes(2, byteorder='big')
        packet_plaintext = header_length_bytes + header + self.build_request_data()
        xtea = XTEACBC(self.encryption_key)
        ciphertext = xtea.crypt_xtea_cbc_encrypt(packet_plaintext)
        payload_length = len(ciphertext)
        framing = payload_length.to_bytes(4, byteorder='little')
        return framing + ciphertext


class LoginTokenGetRequest(BaseLoginRequest):
    def __init__(self, encryption_key):
        super().__init__()
        self.encryption_key = bytes.fromhex(encryption_key)

    def build_request_data(self):
        message = b""
        message += ProtoUtils.encode_varint((1 << 3)
                                            | 0) + ProtoUtils.encode_varint(1)
        return message

    def build_full_packet(self):
        header = self.build_header(277)
        header_length = len(header)
        header_length_bytes = header_length.to_bytes(2, byteorder='big')
        body = self.build_request_data()
        packet_plaintext = header_length_bytes + header + body
        xtea = XTEACBC(self.encryption_key)
        ciphertext = xtea.crypt_xtea_cbc_encrypt(packet_plaintext)
        payload_length = len(ciphertext)
        framing = payload_length.to_bytes(4, byteorder='little')
        return framing + ciphertext


class SystemError:
    ERROR_CODES = {
        0: "SUCCESS",
        1: "ERROR_UNKNOWN",
        2: "ERROR_PARAMS",
        3: "ERROR_AUTH",
        4: "ERROR_SESSION",
        5: "ERROR_SERVER",
        6: "ERROR_FORBIDDEN",
        7: "ERROR_DATA_NOT_EXIST",
        8: "ERROR_DATA_EXIST",
        9: "ERROR_DATA_LIMIT",
        10: "ERROR_QUOTA_LIMIT",
        11: "ERROR_NOT_SUPPORT",
        100: "ERROR_CUSTOM_START",
        101: "ERROR_ACCOUNT_NOT_EXIST",
        102: "ERROR_ACCOUNT_EXIST",
        103: "ERROR_ACCOUNT_LOCKED",
        104: "ERROR_VERSION_TOO_LOW",
        105: "ERROR_CAPTCHA",
        106: "ERROR_INSECURE_PASSWORD",
        107: "ERROR_TOKEN_EXPIRED",
        108: "ERROR_MEMBER_NOT_EXIST",
        109: "ERROR_MEMBER_EXIST",
        110: "ERROR_DECRYPT",
        111: "ERROR_ALREADY_LOGIN",
        112: "ERROR_MISSING_PREPARE_LOGIN",
        113: "ERROR_TAG_NOT_EXIST",
        114: "ERROR_TAG_EXIST",
        115: "ERROR_BUDDY_NOT_EXIST",
        116: "ERROR_BUDDY_EXIST",
        117: "ERROR_REQUEST_NOT_EXIST",
        118: "ERROR_REQUEST_EXIST",
        119: "ERROR_REQUEST_STATUS_INVALID",
        120: "ERROR_SESSION_BLOCKED",
        121: "ERROR_GROUP_NOT_EXIST",
        122: "ERROR_GROUP_EXIST",
        123: "ERROR_DISCUSSION_NOT_EXIST",
        124: "ERROR_DISCUSSION_EXIST",
        125: "ERROR_USER_OFFLINE",
        126: "ERROR_USER_ONLINE",
        127: "ERROR_DUPLICATE_KEY",
        128: "ERROR_REQUEST_STRANGER_BLOCKED",
        129: "ERROR_OTP_NOT_REQUIRE",
        130: "ERROR_OTP_REQUIRE",
        131: "ERROR_OTP_SEND_LIMIT",
        132: "ERROR_OTP_TOKEN_INVALID",
        133: "ERROR_OTP_CODE_INVALID",
        134: "ERROR_OTP_CHANNEL_INVALID",
        135: "ERROR_GAME_ID_INVALID",
        136: "ERROR_GCA_DATA_DECRYPT_FAIL",
        137: "ERROR_GCA_DATA_EXPIRED",
        138: "ERROR_ACCOUNT_STATUS_INVALID",
        139: "ERROR_CLIENT_MOBILE",
        140: "ERROR_CLIENT_NOT_MOBILE",
        141: "ERROR_GOP_REQUEST_INVALID",
        142: "ERROR_RESERVED_NAME",
        143: "ERROR_SESSION_OFFLINE",
        144: "ERROR_FEATURE_DEPRECATED",
        145: "ERROR_APP_UNAVAILABLE",
        156: "ERROR_WRONG_AUTH_TYPE",
        157: "ERROR_EMAIL_NOT_VERIFIED",
        158: "ERROR_COUNTRY_LIMIT",
        159: "ERROR_IP_LIMIT",
        160: "ERROR_TALK_ROOM_LIMIT",
        161: "ERROR_TALK_ROOM_USER_LIMIT",
        162: "ERROR_TALK_ROOM_NOT_EXIST",
        163: "ERROR_TALK_ROOM_JOIN_FORBIDDEN",
        164: "ERROR_TALK_ROOM_STATUS_RESTRICT",
        165: "ERROR_TALK_ROOM_MEMBER_NOT_EXIST",
        166: "ERROR_FACEBOOK_GA_ACCOUNT_CONNECTED",
        167: "ERROR_FACEBOOK_FB_ACCOUNT_CONNECTED",
        168: "ERROR_FACEBOOK_NOT_CONNECTED",
        169: "ERROR_FACEBOOK_TOKEN",
        170: "ERROR_ACCOUNT_NO_PASSWORD",
        171: "ERROR_PACKET_SIZE_EXCEED_LIMIT",
        172: "ERROR_FACEBOOK_FRESH_CONNECTION",
        173: "ERROR_AUTH_USER_BAN",
        174: "ERROR_AUTH_SECURITY_BAN",
        175: "ERROR_GRANT_CONFLICT"
    }

    def __init__(self, code):
        self.code = code
        self.message = self.ERROR_CODES.get(code, "UNKNOWN_ERROR")

    def __str__(self):
        return self.message


class SystemResponse:
    def __init__(self, header, body):
        self.header = header
        self.body = body
        self.result = SystemError(header.get("result", -1))

    @classmethod
    def from_packet(cls, packet):
        header = packet.get("header", {})
        body = packet.get("body", {})
        return cls(header, body)

    def is_success(self):
        return self.result.code == 0


class PacketReceiver(BaseProtobufDecoder):
    def decode_login_prepare_reply(self, body_bytes):
        fields = self.decode_fields(body_bytes)
        reply = {}
        if 1 in fields:
            reply["encrypt_key"] = fields[1][1].hex()
        if 2 in fields:
            reply["data"] = fields[2][1].hex()
        return reply

    def decode_login_reply(self, body_bytes):
        fields = self.decode_fields(body_bytes)
        reply = {}
        if 1 in fields:
            reply["data"] = fields[1][1].hex()
        return reply

    def decode_sso_key_get_reply(self, body_bytes):
        fields = self.decode_fields(body_bytes)
        sso_key = None
        if 1 in fields:
            wire_type, raw_val = fields[1]
            if wire_type == 2:
                try:
                    sso_key = raw_val.decode('utf-8')
                except Exception:
                    sso_key = raw_val.hex()
        return {"sso_key": sso_key}

    def decode_login_prepare_reply_data(self, data):
        fields = self.decode_fields(data)
        salt = fields.get(1, (None, b""))[1]
        verify_code = fields.get(2, (None, b""))[1]
        try:
            salt_str = salt.decode('utf-8')
        except Exception:
            salt_str = salt.hex()
        try:
            verify_code_str = verify_code.decode('utf-8')
        except Exception:
            verify_code_str = verify_code
        return {"salt": salt_str, "verify_code": verify_code_str}

    def decode_login_reply_data(self, data):
        fields = self.decode_fields(data)
        reply = {}
        if 1 in fields:
            reply["uid"] = fields[1][1]
        if 2 in fields:
            reply["session_key"] = fields[2][1].hex()
        return reply

    def decode_login_prepare_reply_proto(self, encrypt_key_hex, data_hex):
        data_bytes = bytes.fromhex(data_hex)
        xtea = XTEACBC(bytes.fromhex(encrypt_key_hex))
        decrypted = xtea.crypt_xtea_cbc_decrypt(data_bytes)
        return self.decode_login_prepare_reply_data(decrypted)

    def decode_login_reply_proto(self, encrypt_key_hex, data_hex):
        data_bytes = bytes.fromhex(data_hex)
        xtea = XTEACBC(bytes.fromhex(encrypt_key_hex))
        decrypted = xtea.crypt_xtea_cbc_decrypt(data_bytes)
        return self.decode_login_reply_data(decrypted)

    def decode_packet(self, framing_hex, payload_hex, encryption_key_hex=None):
        framing_bytes = binascii.unhexlify(framing_hex)
        payload_length = int.from_bytes(framing_bytes, byteorder='little')
        payload_bytes = binascii.unhexlify(payload_hex)

        if payload_length < 2:
            return {"header": {}, "message_type": "UNKNOWN", "body": {}}

        header_length = int.from_bytes(payload_bytes[:2], byteorder='big')

        if header_length > (payload_length - 2):
            ciphertext = payload_bytes
            if encryption_key_hex:
                xtea = XTEACBC(bytes.fromhex(encryption_key_hex))
                decrypted = xtea.crypt_xtea_cbc_decrypt(ciphertext)
                if len(decrypted) < 2:
                    header_decoded = {}
                    body_bytes = b""
                else:
                    dec_header_length = int.from_bytes(
                        decrypted[:2], byteorder='big')
                    header_bytes = decrypted[2:2+dec_header_length]
                    body_bytes = decrypted[2+dec_header_length:]
                    header_decoded = self.decode_client_packet_header(
                        header_bytes)
            else:
                header_decoded = {}
                body_bytes = b""
        else:
            header_bytes = payload_bytes[2: 2 + header_length]
            body_bytes = payload_bytes[2 + header_length:]
            header_decoded = self.decode_client_packet_header(header_bytes)

        cmd_type = header_decoded.get("command_type")
        cmd = header_decoded.get("command")
        message_type = "UNKNOWN"
        body_decoded = {}

        if body_bytes:
            if cmd_type == 3 and cmd == 256:
                message_type = "LoginPrepareReply"
                body_decoded = self.decode_login_prepare_reply(body_bytes)
            elif cmd_type == 3 and (cmd == 257 or cmd == 259):
                message_type = "LoginReply"
                body_decoded = self.decode_login_reply(body_bytes)
            elif (cmd_type == 3 or cmd_type == 4) and cmd in [274, 294, 442]:
                message_type = "SsoKeyGetReply"
                body_decoded = self.decode_sso_key_get_reply(body_bytes)

        return {
            "header": header_decoded,
            "message_type": message_type,
            "body": body_decoded
        }


class EncryptionKeyGenerator:
    def __init__(self, password: str, salt: str, third_param: str):
        self.password = password
        self.salt = salt
        self.third_param = third_param

    def md5_hash(self, s: str) -> str:
        return hashlib.md5(s.encode()).hexdigest()

    def sha256_digest(self, s: str) -> bytes:
        return hashlib.sha256(s.encode()).digest()

    def generate(self) -> bytes:
        md5_pass = self.md5_hash(self.password)
        digest_step2 = self.sha256_digest(md5_pass + self.salt)
        hex_step2 = digest_step2.hex()
        final_digest = self.sha256_digest(hex_step2 + self.third_param)
        return final_digest[:16]


class TCPClient:
    def __init__(self, server_ip="103.247.205.15", server_port=19000, proxy_url=None):
        self.server_ip = server_ip
        self.server_port = server_port
        self.proxy_url = proxy_url
        self.sock = None

    def connect(self):
        if not self.proxy_url:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.server_ip, self.server_port))
            self.sock = s
            return

        p = urlparse(self.proxy_url)
        scheme = p.scheme.lower()
        proxy_host = p.hostname
        proxy_port = p.port or 1080
        proxy_user = p.username
        proxy_pass = p.password
        rdns = scheme.endswith('h')

        s = socks.socksocket()
        s.set_proxy(
            proxy_type=socks.SOCKS5,
            addr=proxy_host,
            port=proxy_port,
            rdns=rdns,
            username=proxy_user,
            password=proxy_pass
        )
        s.connect((self.server_ip, self.server_port))
        self.sock = s

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def send_message(self, message):
        responses = []
        try:
            if not self.sock:
                return responses
            self.sock.sendall(message)
            header = self.sock.recv(4)
            if not header:
                return responses
            length = struct.unpack("<I", header)[0]
            payload = self.recv_all(length)
            responses.extend([header, payload])
        except Exception:
            pass
        return responses

    def recv_all(self, length):
        data = b""
        while len(data) < length:
            more = self.sock.recv(length - len(data))
            if not more:
                raise EOFError("Socket closed prematurely")
            data += more
        return data


def login_and_get_keys(account, password, proxy=None, max_retries=3):
    start_time = time.time()
    last_error_code = -5999

    for attempt in range(1, max_retries + 1):
        tcp_client = None
        try:
            tcp_client = TCPClient(proxy_url=proxy)
            pd = PacketReceiver()
            tcp_client.connect()
            prep = None
            resp = tcp_client.send_message(
                LoginPrepareRequest(account)
                .build_full_packet()
            )
            if len(resp) < 2:
                last_error_code = -1
                break

            prep = SystemResponse.from_packet(
                pd.decode_packet(resp[0].hex(), resp[1].hex())
            )
            if not prep or prep.result.code == 105 or last_error_code == -1:
                tcp_client.close()
                continue
            if not prep.is_success():
                last_error_code = prep.result.code
                if last_error_code not in [-1, -2, -3, -6, 110]:
                    return {
                        "code": last_error_code,
                        "duration": round(time.time() - start_time, 2),
                        "msg": prep.result.message,
                    }
                tcp_client.close()
                continue
            proto = pd.decode_login_prepare_reply_proto(
                prep.body["encrypt_key"], prep.body["data"]
            )
            if not (proto.get("salt") and proto.get("verify_code")):
                last_error_code = -2
                tcp_client.close()
                continue
            enc_key = EncryptionKeyGenerator(
                password, proto["salt"], proto["verify_code"]
            ).generate()
            resp = tcp_client.send_message(
                LoginRequestHandler(password, enc_key.hex())
                .build_full_packet()
            )
            if len(resp) < 2:
                last_error_code = -3
                tcp_client.close()
                continue

            login = SystemResponse.from_packet(
                pd.decode_packet(resp[0].hex(), resp[1].hex())
            )
            if not login.is_success():
                last_error_code = login.result.code
                if last_error_code not in [-1, -2, -3, -6, 110]:
                    return {
                        "code": last_error_code,
                        "duration": round(time.time() - start_time, 2)
                    }
                tcp_client.close()
                continue
            lp = pd.decode_login_reply_proto(enc_key.hex(), login.body["data"])
            uid = lp.get("uid")
            session_key = lp.get("session_key")
            if not session_key:
                last_error_code = -3
                tcp_client.close()
                continue
            resp = tcp_client.send_message(
                LoginTokenGetRequest(session_key).build_full_packet()
            )
            _ = SystemResponse.from_packet(
                pd.decode_packet(resp[0].hex(), resp[1].hex(), session_key)
            )
            packets = [
                EmptyPacket(session_key, t).build_full_packet()
                for t in (278, 511, 276, 278, 442, 342)
            ]
            tcp_client.sock.sendall(b"".join(packets))
            tcp_client.sock.settimeout(0.5)

            merged = {}
            timeout_count = 0
            while timeout_count < 1:
                try:
                    hdr = tcp_client.sock.recv(4)
                    if not hdr:
                        break
                    ln = struct.unpack("<I", hdr)[0]
                    data = tcp_client.recv_all(ln)
                    dec = pd.decode_packet(hdr.hex(), data.hex(), session_key)
                    mtype = dec.get("message_type", "UNKNOWN")
                    if mtype == "UNKNOWN":
                        continue
                    body = dec.get("body", {})
                    if mtype in merged:
                        if not isinstance(merged[mtype], list):
                            merged[mtype] = [merged[mtype]]
                        merged[mtype].append(body)
                    else:
                        merged[mtype] = body
                except socket.timeout:
                    timeout_count += 1
                    continue
                except Exception:
                    break
            sso_key = None
            if "SsoKeyGetReply" in merged:
                sso_data = merged["SsoKeyGetReply"]
                if isinstance(sso_data, list):
                    sso_data = sso_data[0]
                sso_key = sso_data.get("sso_key")
            if session_key and sso_key and len(sso_key) >= 8:
                return {
                    "code": 0,
                    "uid": uid,
                    "session_key": session_key,
                    "SsoKeyGetReply": {"sso_key": sso_key},
                    "duration": round(time.time() - start_time, 2),
                    "attempts": attempt
                }
            else:
                last_error_code = -4
                tcp_client.close()
                continue

        except Exception as ex:
            last_error_code = -5
            print(f"[login] Exception on attempt {attempt}: {ex}")
            if tcp_client:
                tcp_client.close()
            continue

        finally:
            if tcp_client:
                tcp_client.close()
    return {
        "code": last_error_code,
        "duration": round(time.time() - start_time, 2),
        "attempts": max_retries
    }


app = Flask(__name__)


@app.route('/api/login', methods=['GET'])
def api_login_get():
    username = request.args.get('username')
    password = request.args.get('password')
    proxy = request.args.get('proxy')

    if not username or not password:
        return jsonify({"code": -1, "error": "Missing parameters"}), 400

    try:
        result = login_and_get_keys(username, password, proxy)
    except Exception as e:
        return jsonify({"code": -999, "error": str(e)}), 500

    return jsonify(result), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
