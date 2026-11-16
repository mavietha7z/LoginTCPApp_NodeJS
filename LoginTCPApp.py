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
    HEADER_FIELD_NAMES = {
        1: "version",
        2: "id",
        3: "command_type",
        4: "command",
        5: "result",
        6: "timestamp",
        7: "fragment_number",
        8: "fragment_index"
    }

    def decode_varint(self, data, offset):
        shift = 0
        result = 0
        while True:
            if offset >= len(data):
                raise Exception("Unexpected end of data while parsing varint")
            current_byte = data[offset]
            result |= (current_byte & 0x7F) << shift
            offset += 1
            if not (current_byte & 0x80):
                break
            shift += 7
        return result, offset

    def decode_length_delimited(self, data, offset):
        length, offset = self.decode_varint(data, offset)
        value = data[offset:offset + length]
        offset += length
        return value, offset

    def decode_fixed64(self, data, offset):
        value = data[offset:offset + 8]
        offset += 8
        return value, offset

    def decode_fixed32(self, data, offset):
        value = data[offset:offset + 4]
        offset += 4
        return value, offset

    def decode_protobuf_fields(self, protobuf_data):
        offset = 0
        fields = {}
        while offset < len(protobuf_data):
            field_key, offset = self.decode_varint(protobuf_data, offset)
            field_number = field_key >> 3
            wire_type = field_key & 0x07
            if wire_type == 0:
                value, offset = self.decode_varint(protobuf_data, offset)
            elif wire_type == 1:
                value, offset = self.decode_fixed64(protobuf_data, offset)
            elif wire_type == 2:
                value, offset = self.decode_length_delimited(
                    protobuf_data, offset)
            elif wire_type == 5:
                value, offset = self.decode_fixed32(protobuf_data, offset)
            else:
                raise Exception(
                    f"Unsupported wire type: {wire_type} for tag: {field_number}")
            fields[field_number] = (wire_type, value)
        return fields

    def decode_packet_header(self, header_bytes):
        fields = self.decode_protobuf_fields(header_bytes)
        header = {}
        for field_number, (wire_type, value) in fields.items():
            field_name = self.HEADER_FIELD_NAMES.get(field_number, f"unknown_field_{field_number}")
            if wire_type == 0:
                header[field_name] = value
            elif wire_type in (1, 5):
                header[field_name] = int.from_bytes(value, byteorder='little')
            elif wire_type == 2:
                header[field_name] = value.hex()
            else:
                header[field_name] = value
        return header


class PacketBuilder(BaseProtobufDecoder):
    def encode_varint(self, value):
        encoded_bytes = bytearray()
        while True:
            next_seven_bits = value & 0x7F
            value >>= 7
            if value:
                encoded_bytes.append(next_seven_bits | 0x80)
            else:
                encoded_bytes.append(next_seven_bits)
                break
        return bytes(encoded_bytes)

    def build_packet(self, header_bytes, body_bytes=None):
        if body_bytes is None:
            body_bytes = b""
        header_length = len(header_bytes)
        payload = header_length.to_bytes(
            2, byteorder='big') + header_bytes + body_bytes
        framing = len(payload).to_bytes(4, byteorder='little')
        return framing + payload


UNSIGNED_32_BIT_MASK = 0xffffffff


class Lrand48:
    def __init__(self, seed):
        self.multiplier = 0x5DEECE66D
        self.increment = 0xB
        self.modulus = 1 << 48
        self.state = ((seed & 0xffffffff) << 16) | 0x330E

    def next_value(self):
        self.state = (self.state * self.multiplier + self.increment) & (self.modulus - 1)
        return self.state >> 17


class XteaCustom:
    BLOCK_SIZE = 8
    DELTA = 1640531527

    def __init__(self, key_bytes: bytes, endian: str = 'little'):
        if len(key_bytes) != 16:
            raise ValueError("Key must be 16 bytes!")
        self.key_words = self._split_key_into_words(key_bytes, endian)
        self.key_bytes = key_bytes
        self.endian = endian

    @staticmethod
    def _split_key_into_words(key_bytes: bytes, endian: str = 'little'):
        return [int.from_bytes(key_bytes[word_index*4:(word_index+1)*4], endian) for word_index in range(4)]

    @staticmethod
    def _add_unsigned_32(first, second):
        return (first + second) & UNSIGNED_32_BIT_MASK

    @staticmethod
    def _subtract_unsigned_32(first, second):
        return (first - second) & UNSIGNED_32_BIT_MASK

    @staticmethod
    def _decrypt_block(left, right, key_words: list, round_count: int = 32, round_delta: int = 1640531527):
        round_sum = (-957401312) & UNSIGNED_32_BIT_MASK
        for _ in range(round_count):
            left_mix = (left + ((16 * left) ^ (left >> 5))) & UNSIGNED_32_BIT_MASK
            first_key_index = ((round_sum >> 9) & 0xC) >> 2
            first_key_part = (round_sum + key_words[first_key_index]) & UNSIGNED_32_BIT_MASK
            right = XteaCustom._subtract_unsigned_32(right, left_mix ^ first_key_part)
            right_mix = (right + ((16 * right) ^ (right >> 5))) & UNSIGNED_32_BIT_MASK
            second_key_index = (((round_sum & 0xff) + 71) & 3)
            second_key_part = (round_sum + key_words[second_key_index] + round_delta) & UNSIGNED_32_BIT_MASK
            left = XteaCustom._subtract_unsigned_32(left, right_mix ^ second_key_part)
            round_sum = XteaCustom._add_unsigned_32(round_sum, round_delta)
        return left, right

    @staticmethod
    def _bytes_to_word_pair(block_bytes: bytes):
        if len(block_bytes) != 8:
            raise ValueError("Block must be 8 bytes!")
        left_word = int.from_bytes(block_bytes[0:4], 'little')
        right_word = int.from_bytes(block_bytes[4:8], 'little')
        return (left_word, right_word)

    @staticmethod
    def remove_padding(data: bytes, block_size: int = 8):
        if not data:
            raise ValueError("Data is empty!")
        padding_length = data[-1]
        if padding_length < 1 or padding_length > block_size:
            raise ValueError(f"Invalid padding value: {padding_length}")
        if data[-padding_length:] != bytes([padding_length] * padding_length):
            raise ValueError("Invalid padding!")
        return data[:-padding_length]

    def decrypt(self, ciphertext: bytes, endian='little') -> bytes:
        if len(ciphertext) % self.BLOCK_SIZE != 0 or len(ciphertext) < self.BLOCK_SIZE:
            raise ValueError("Ciphertext length invalid!")
        block_count = len(ciphertext) // self.BLOCK_SIZE
        blocks = [self._bytes_to_word_pair(
            ciphertext[block_index * self.BLOCK_SIZE:(block_index + 1) * self.BLOCK_SIZE]) for block_index in range(block_count)]
        initial_block = blocks[0]
        decrypted = b""
        previous_block = initial_block
        for block in blocks[1:]:
            cipher_left, cipher_right = block
            decrypted_left, decrypted_right = self._decrypt_block(
                cipher_left, cipher_right, self.key_words, round_count=32, round_delta=self.DELTA)
            previous_left, previous_right = previous_block
            plain_left = decrypted_left ^ previous_left
            plain_right = decrypted_right ^ previous_right
            decrypted += plain_left.to_bytes(4, 'little') + plain_right.to_bytes(4, 'little')
            previous_block = block
        output_length = len(ciphertext) - 16
        padded_data = decrypted[:output_length]
        return self.remove_padding(padded_data, self.BLOCK_SIZE)

    def encrypt(self, plaintext: bytes, initialization_vector: bytes = None) -> bytes:
        plaintext_length = len(plaintext)
        full_block_count = plaintext_length >> 3
        full_blocks_byte_length = 8 * full_block_count
        block_loop_count = full_block_count
        output_size = full_blocks_byte_length + 24
        output_words = [0] * (output_size // 4)
        if initialization_vector is not None:
            if len(initialization_vector) != 8:
                raise ValueError("IV phải có độ dài 8 byte")
            seed_left = int.from_bytes(initialization_vector[0:4], 'little')
            cipher_left = int.from_bytes(initialization_vector[4:8], 'little')
            cipher_right = seed_left | (cipher_left >> 31)
        else:
            random_generator = Lrand48(int(time.time()))
            seed_left = random_generator.next_value() & 0xffffffff
            cipher_left = random_generator.next_value() & 0xffffffff
            cipher_right = seed_left | (cipher_left >> 31)
        round_sum = 0
        delta = 0x61C88647
        round_count = 32
        rolling_high = cipher_right
        rolling_low = cipher_left
        for _ in range(round_count):
            mix_value = (cipher_right + ((16 * cipher_right) ^ (cipher_right >> 5))) & 0xffffffff
            first_key_word = int.from_bytes(
                self.key_bytes[((round_sum & 3) * 4):((round_sum & 3) * 4 + 4)], 'little')
            key_value = (round_sum + first_key_word) & 0xffffffff
            cipher_left = (cipher_left + (mix_value ^ key_value)) & 0xffffffff
            mix_value = (cipher_left + ((16 * cipher_left) ^ (cipher_left >> 5))) & 0xffffffff
            second_key_index = (((round_sum - delta) >> 9) & 0xC) >> 2
            second_key_word = int.from_bytes(
                self.key_bytes[(second_key_index * 4):(second_key_index * 4 + 4)], 'little')
            key_value = (round_sum + second_key_word) & 0xffffffff
            key_value = (key_value - delta) & 0xffffffff
            cipher_right = (cipher_right + (mix_value ^ key_value)) & 0xffffffff
            round_sum = (round_sum - delta) & 0xffffffff
        output_words[0] = cipher_left
        output_words[1] = cipher_right
        input_offset = 0
        output_index = 2
        for block_index in range(block_loop_count):
            plain_left = int.from_bytes(plaintext[input_offset:input_offset+4], 'little')
            plain_right = int.from_bytes(plaintext[input_offset+4:input_offset+8], 'little')
            input_offset += 8
            plain_pair = ((plain_right & 0xffffffff) << 32) | (plain_left & 0xffffffff)
            rolling_pair = ((rolling_high & 0xffffffff) << 32) | (rolling_low & 0xffffffff)
            rolling_sum = (plain_pair + rolling_pair) & 0xffffffffffffffff
            rolling_high = (rolling_sum >> 32) & 0xffffffff
            rolling_low = (rolling_low + plain_left) & 0xffffffff
            cipher_right = cipher_right ^ plain_right
            block_left = plain_left ^ cipher_left
            block_round_sum = 0
            for round_index in range(32):
                mix_value = (cipher_right + ((16 * cipher_right) ^ (cipher_right >> 5))) & 0xffffffff
                first_key_word = int.from_bytes(
                    self.key_bytes[((block_round_sum & 3) * 4):((block_round_sum & 3) * 4 + 4)], 'little')
                key_value = (block_round_sum + first_key_word) & 0xffffffff
                block_left = (block_left + (mix_value ^ key_value)) & 0xffffffff
                mix_value = (block_left + ((16 * block_left) ^ (block_left >> 5))) & 0xffffffff
                second_key_index = (((block_round_sum - delta) >> 9) & 0xC) >> 2
                second_key_word = int.from_bytes(
                    self.key_bytes[(second_key_index * 4):(second_key_index * 4 + 4)], 'little')
                key_value = (block_round_sum + second_key_word) & 0xffffffff
                key_value = (key_value - delta) & 0xffffffff
                cipher_right = (cipher_right + (mix_value ^ key_value)) & 0xffffffff
                block_round_sum = (block_round_sum - delta) & 0xffffffff
            cipher_left = block_left
            output_words[output_index] = block_left
            output_words[output_index + 1] = cipher_right
            output_index += 2
            remainder = plaintext_length & 7
            if remainder > 0:
                tail_bytes = plaintext[input_offset:input_offset+remainder]
            else:
                tail_bytes = b""
        padding_block = self.build_padding_block(tail_bytes)
        padding_value = int.from_bytes(padding_block, 'little')
        padding_cipher_left = (padding_value & 0xffffffff) ^ cipher_left
        padding_cipher_right = ((padding_value >> 32) & 0xffffffff) ^ cipher_right
        padding_round_sum = 0
        for round_index in range(32):
            mix_value = (padding_cipher_right + ((16 * padding_cipher_right) ^ (padding_cipher_right >> 5))) & 0xffffffff
            first_key_word = int.from_bytes(
                self.key_bytes[((padding_round_sum & 3) * 4):((padding_round_sum & 3) * 4 + 4)], 'little')
            key_value = (padding_round_sum + first_key_word) & 0xffffffff
            padding_cipher_left = (padding_cipher_left + (mix_value ^ key_value)) & 0xffffffff
            mix_value = (padding_cipher_left + ((16 * padding_cipher_left) ^ (padding_cipher_left >> 5))) & 0xffffffff
            second_key_index = (((padding_round_sum - delta) >> 9) & 0xC) >> 2
            second_key_word = int.from_bytes(
                self.key_bytes[(second_key_index * 4):(second_key_index * 4 + 4)], 'little')
            key_value = (padding_round_sum + second_key_word) & 0xffffffff
            key_value = (key_value - delta) & 0xffffffff
            padding_cipher_right = (padding_cipher_right + (mix_value ^ key_value)) & 0xffffffff
            padding_round_sum = (padding_round_sum - delta) & 0xffffffff
        output_words[output_index] = padding_cipher_left
        output_words[output_index + 1] = padding_cipher_right
        output_index += 2
        final_rolling_pair = ((rolling_high & 0xffffffff) << 32) | (rolling_low & 0xffffffff)
        final_rolling_sum = (final_rolling_pair + padding_value) & 0xffffffffffffffff
        checksum_high = (final_rolling_sum >> 32) & 0xffffffff
        checksum_low = (rolling_low + (padding_value & 0xffffffff)) & 0xffffffff
        checksum_cipher_left = padding_cipher_left ^ checksum_low
        checksum_cipher_right = padding_cipher_right ^ checksum_high
        checksum_round_sum = 0
        for round_index in range(32):
            mix_value = (checksum_cipher_right + ((16 * checksum_cipher_right) ^ (checksum_cipher_right >> 5))) & 0xffffffff
            first_key_word = int.from_bytes(
                self.key_bytes[((checksum_round_sum & 3) * 4):((checksum_round_sum & 3) * 4 + 4)], 'little')
            key_value = (checksum_round_sum + first_key_word) & 0xffffffff
            checksum_cipher_left = (checksum_cipher_left + (mix_value ^ key_value)) & 0xffffffff
            mix_value = (checksum_cipher_left + ((16 * checksum_cipher_left) ^ (checksum_cipher_left >> 5))) & 0xffffffff
            second_key_index = (((checksum_round_sum - delta) >> 9) & 0xC) >> 2
            second_key_word = int.from_bytes(
                self.key_bytes[(second_key_index * 4):(second_key_index * 4 + 4)], 'little')
            key_value = (checksum_round_sum + second_key_word) & 0xffffffff
            key_value = (key_value - delta) & 0xffffffff
            checksum_cipher_right = (checksum_cipher_right + (mix_value ^ key_value)) & 0xffffffff
            checksum_round_sum = (checksum_round_sum - delta) & 0xffffffff
        output_words[output_index] = checksum_cipher_left
        output_words[output_index + 1] = checksum_cipher_right
        output_index += 2
        result = b"".join(word.to_bytes(4, 'little') for word in output_words)
        return result

    def build_padding_block(self, plaintext: bytes) -> bytes:
        length = len(plaintext)
        remainder = length & 7
        padded_block = bytearray(8)
        if remainder != 0:
            padded_block[:remainder] = plaintext[-remainder:]
        padding_length = 8 - remainder
        for padding_index in range(padding_length):
            padded_block[remainder + padding_index] = padding_length
        return padded_block


class ProtobufEncoder:
    @staticmethod
    def encode_varint(value):
        result = bytearray()
        while True:
            next_seven_bits = value & 0x7F
            value >>= 7
            if value:
                result.append(next_seven_bits | 0x80)
            else:
                result.append(next_seven_bits)
                break
        return bytes(result)

    @classmethod
    def encode_length_delimited(cls, data_bytes):
        return cls.encode_varint(len(data_bytes)) + data_bytes


class BaseLoginRequest:
    def __init__(self):
        self.random_key = os.urandom(16)
        self.timestamp = int(time.time())

    def build_header(self, command):
        header_fields = {
            1: 285212918,
            2: hash(uuid.getnode()),
            3: 2,
            4: command,
            6: int(time.time()),
        }
        message = b""
        for field_number, value in header_fields.items():
            field_key = ProtobufEncoder.encode_varint((field_number << 3) | 0)
            message += field_key + ProtobufEncoder.encode_varint(value)
        return message

    def encrypt_data(self, data_bytes):
        cipher = XteaCustom(self.random_key)
        return cipher.encrypt(data_bytes)

    def build_encrypted_body(self, key_bytes, data_bytes, key_field_number=1, data_field_number=2):
        message = b""
        message += ProtobufEncoder.encode_varint((key_field_number << 3) | 2) + \
            ProtobufEncoder.encode_length_delimited(key_bytes)
        message += ProtobufEncoder.encode_varint((data_field_number << 3) | 2) + \
            ProtobufEncoder.encode_length_delimited(data_bytes)
        return message

    def build_full_packet(self, request_data_builder, command):
        data_bytes = request_data_builder()
        ciphertext = self.encrypt_data(data_bytes)
        body = self.build_encrypted_body(self.random_key, ciphertext)
        header = self.build_header(command)
        packet_builder = PacketBuilder()
        return packet_builder.build_packet(header, body)


class LoginPrepareRequest(BaseLoginRequest):
    def __init__(self, account):
        super().__init__()
        self.account = account
        self.authentication_type = 0
        self.account_type = 2 if re.match(
            r"[^@]+@[^@]+\.[^@]+", account) else 1
        self.client_type = 4352
        self.client_version = 246

    def build_request_data(self):
        message = b""
        message += ProtobufEncoder.encode_varint((1 << 3) | 0) + \
            ProtobufEncoder.encode_varint(self.authentication_type)
        message += ProtobufEncoder.encode_varint((2 << 3) | 0) + \
            ProtobufEncoder.encode_varint(self.account_type)

        account_bytes = self.account.encode('utf-8')
        message += ProtobufEncoder.encode_varint((3 << 3) | 2) + \
            ProtobufEncoder.encode_length_delimited(account_bytes)

        message += ProtobufEncoder.encode_varint((4 << 3) | 0) + \
            ProtobufEncoder.encode_varint(self.client_type)
        message += ProtobufEncoder.encode_varint((5 << 3) | 0) + \
            ProtobufEncoder.encode_varint(self.client_version)
        return message

    def build_full_packet(self):
        return super().build_full_packet(self.build_request_data, command=256)


class LoginRequest(BaseLoginRequest):
    def __init__(self, password=None, encryption_key_hex=None):
        self.random_key = bytes.fromhex(encryption_key_hex)
        self.device_identifier = str(hash(uuid.getnode())).encode('utf-8')
        self.login_mode = 0
        self.password_hash = hashlib.md5(password.encode(
            'utf-8')).hexdigest().encode('utf-8') if password else None
        self.user_status = 4608
        self.timestamp = int(time.time())

    def build_request_data(self):
        message = b""
        message += ProtobufEncoder.encode_varint((1 << 3) | 2) + \
            ProtobufEncoder.encode_length_delimited(self.password_hash)
        message += ProtobufEncoder.encode_varint((2 << 3) | 0) + \
            ProtobufEncoder.encode_varint(self.login_mode)
        user_status_message = self.build_user_status_message()
        message += ProtobufEncoder.encode_varint((3 << 3) | 2) + \
            ProtobufEncoder.encode_length_delimited(user_status_message)
        message += ProtobufEncoder.encode_varint((4 << 3) | 2) + \
            ProtobufEncoder.encode_length_delimited(self.device_identifier)
        return message

    def build_user_status_message(self):
        message = b""
        message += ProtobufEncoder.encode_varint((2 << 3) | 0) + \
            ProtobufEncoder.encode_varint(self.user_status)
        return message

    def build_full_packet(self):
        data_bytes = self.build_request_data()
        ciphertext = self.encrypt_data(data_bytes)
        header = self.build_header(257)
        body = ProtobufEncoder.encode_varint(
            (1 << 3) | 2) + ProtobufEncoder.encode_length_delimited(ciphertext)
        packet_builder = PacketBuilder()
        return packet_builder.build_packet(header, body)


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
        cipher = XteaCustom(self.encryption_key)
        ciphertext = cipher.encrypt(packet_plaintext)
        payload_length = len(ciphertext)
        framing = payload_length.to_bytes(4, byteorder='little')
        return framing + ciphertext


class LoginTokenGetRequest(BaseLoginRequest):
    def __init__(self, encryption_key):
        super().__init__()
        self.encryption_key = bytes.fromhex(encryption_key)

    def build_request_data(self):
        message = b""
        message += ProtobufEncoder.encode_varint((1 << 3)
                                                 | 0) + ProtobufEncoder.encode_varint(1)
        return message

    def build_full_packet(self):
        header = self.build_header(277)
        header_length = len(header)
        header_length_bytes = header_length.to_bytes(2, byteorder='big')
        body = self.build_request_data()
        packet_plaintext = header_length_bytes + header + body
        cipher = XteaCustom(self.encryption_key)
        ciphertext = cipher.encrypt(packet_plaintext)
        payload_length = len(ciphertext)
        framing = payload_length.to_bytes(4, byteorder='little')
        return framing + ciphertext


class SystemErrorCode:
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
        self.result = SystemErrorCode(header.get("result", -1))

    @classmethod
    def from_packet(cls, packet):
        header = packet.get("header", {})
        body = packet.get("body", {})
        return cls(header, body)

    def is_success(self):
        return self.result.code == 0


class PacketReceiver(BaseProtobufDecoder):
    def decode_login_prepare_reply(self, body_bytes):
        fields = self.decode_protobuf_fields(body_bytes)
        reply = {}
        if 1 in fields:
            reply["encrypt_key"] = fields[1][1].hex()
        if 2 in fields:
            reply["data"] = fields[2][1].hex()
        return reply

    def decode_login_reply(self, body_bytes):
        fields = self.decode_protobuf_fields(body_bytes)
        reply = {}
        if 1 in fields:
            reply["data"] = fields[1][1].hex()
        return reply

    def decode_sso_key_get_reply(self, body_bytes):
        fields = self.decode_protobuf_fields(body_bytes)
        sso_key = None
        if 1 in fields:
            wire_type, raw_value = fields[1]
            if wire_type == 2:
                try:
                    sso_key = raw_value.decode('utf-8')
                except Exception:
                    sso_key = raw_value.hex()
        return {"sso_key": sso_key}

    def decode_login_prepare_reply_data(self, data):
        fields = self.decode_protobuf_fields(data)
        salt = fields.get(1, (None, b""))[1]
        verify_code = fields.get(2, (None, b""))[1]
        try:
            salt_text = salt.decode('utf-8')
        except Exception:
            salt_text = salt.hex()
        try:
            verify_code_text = verify_code.decode('utf-8')
        except Exception:
            verify_code_text = verify_code
        return {"salt": salt_text, "verify_code": verify_code_text}

    def decode_login_reply_data(self, data):
        fields = self.decode_protobuf_fields(data)
        reply = {}
        if 1 in fields:
            reply["uid"] = fields[1][1]
        if 2 in fields:
            reply["session_key"] = fields[2][1].hex()
        return reply

    def decrypt_login_prepare_reply_data(self, encrypt_key_hex, data_hex):
        data_bytes = bytes.fromhex(data_hex)
        cipher = XteaCustom(bytes.fromhex(encrypt_key_hex))
        decrypted = cipher.decrypt(data_bytes)
        return self.decode_login_prepare_reply_data(decrypted)

    def decrypt_login_reply_data(self, encrypt_key_hex, data_hex):
        data_bytes = bytes.fromhex(data_hex)
        cipher = XteaCustom(bytes.fromhex(encrypt_key_hex))
        decrypted = cipher.decrypt(data_bytes)
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
                cipher = XteaCustom(bytes.fromhex(encryption_key_hex))
                decrypted = cipher.decrypt(ciphertext)
                if len(decrypted) < 2:
                    decoded_header = {}
                    body_bytes = b""
                else:
                    decrypted_header_length = int.from_bytes(
                        decrypted[:2], byteorder='big')
                    header_bytes = decrypted[2:2+decrypted_header_length]
                    body_bytes = decrypted[2+decrypted_header_length:]
                    decoded_header = self.decode_packet_header(
                        header_bytes)
            else:
                decoded_header = {}
                body_bytes = b""
        else:
            header_bytes = payload_bytes[2: 2 + header_length]
            body_bytes = payload_bytes[2 + header_length:]
            decoded_header = self.decode_packet_header(header_bytes)

        command_type = decoded_header.get("command_type")
        command = decoded_header.get("command")
        message_type = "UNKNOWN"
        decoded_body = {}

        if body_bytes:
            if command_type == 3 and command == 256:
                message_type = "LoginPrepareReply"
                decoded_body = self.decode_login_prepare_reply(body_bytes)
            elif command_type == 3 and (command == 257 or command == 259):
                message_type = "LoginReply"
                decoded_body = self.decode_login_reply(body_bytes)
            elif (command_type == 3 or command_type == 4) and command in [274, 294, 442]:
                message_type = "SsoKeyGetReply"
                decoded_body = self.decode_sso_key_get_reply(body_bytes)

        return {
            "header": decoded_header,
            "message_type": message_type,
            "body": decoded_body
        }


class EncryptionKeyGenerator:
    def __init__(self, password: str, salt: str, verify_code: str):
        self.password = password
        self.salt = salt
        self.verify_code = verify_code

    def md5_hash(self, text: str) -> str:
        return hashlib.md5(text.encode()).hexdigest()

    def sha256_digest(self, text: str) -> bytes:
        return hashlib.sha256(text.encode()).digest()

    def generate(self) -> bytes:
        password_digest = self.md5_hash(self.password)
        salted_digest = self.sha256_digest(password_digest + self.salt)
        salted_digest_hex = salted_digest.hex()
        final_digest = self.sha256_digest(salted_digest_hex + self.verify_code)
        return final_digest[:16]


class TcpClient:
    def __init__(self, server_ip="103.247.205.15", server_port=19000, proxy_url=None):
        self.server_ip = server_ip
        self.server_port = server_port
        self.proxy_url = proxy_url
        self.connection_socket = None

    def connect(self):
        if not self.proxy_url:
            connection_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connection_socket.connect((self.server_ip, self.server_port))
            self.connection_socket = connection_socket
            return

        proxy = urlparse(self.proxy_url)
        scheme = proxy.scheme.lower()
        proxy_host = proxy.hostname
        proxy_port = proxy.port or 1080
        proxy_username = proxy.username
        proxy_password = proxy.password
        resolve_dns_remotely = scheme.endswith('h')

        connection_socket = socks.socksocket()
        connection_socket.set_proxy(
            proxy_type=socks.SOCKS5,
            addr=proxy_host,
            port=proxy_port,
            rdns=resolve_dns_remotely,
            username=proxy_username,
            password=proxy_password
        )
        connection_socket.connect((self.server_ip, self.server_port))
        self.connection_socket = connection_socket

    def close(self):
        if self.connection_socket:
            self.connection_socket.close()
            self.connection_socket = None

    def send_message(self, message):
        responses = []
        try:
            if not self.connection_socket:
                return responses
            self.connection_socket.sendall(message)
            frame_header = self.connection_socket.recv(4)
            if not frame_header:
                return responses
            length = struct.unpack("<I", frame_header)[0]
            payload = self.receive_exactly(length)
            responses.extend([frame_header, payload])
        except Exception:
            pass
        return responses

    def receive_exactly(self, length):
        data = b""
        while len(data) < length:
            chunk = self.connection_socket.recv(length - len(data))
            if not chunk:
                raise EOFError("Socket closed prematurely")
            data += chunk
        return data


def login_and_get_keys(account, password, proxy=None, maximum_retries=3):
    start_time = time.time()
    last_error_code = -5999

    for attempt in range(1, maximum_retries + 1):
        tcp_client = None
        try:
            tcp_client = TcpClient(proxy_url=proxy)
            packet_receiver = PacketReceiver()
            tcp_client.connect()
            login_prepare_response = None
            response_frames = tcp_client.send_message(
                LoginPrepareRequest(account)
                .build_full_packet()
            )
            if len(response_frames) < 2:
                last_error_code = -1
                break

            login_prepare_response = SystemResponse.from_packet(
                packet_receiver.decode_packet(response_frames[0].hex(), response_frames[1].hex())
            )
            if not login_prepare_response or login_prepare_response.result.code == 105 or last_error_code == -1:
                tcp_client.close()
                continue
            if not login_prepare_response.is_success():
                last_error_code = login_prepare_response.result.code
                if last_error_code not in [-1, -2, -3, -6, 110]:
                    return {
                        "code": last_error_code,
                        "duration": round(time.time() - start_time, 2),
                        "msg": login_prepare_response.result.message,
                    }
                tcp_client.close()
                continue
            login_prepare_data = packet_receiver.decrypt_login_prepare_reply_data(
                login_prepare_response.body["encrypt_key"], login_prepare_response.body["data"]
            )
            if not (login_prepare_data.get("salt") and login_prepare_data.get("verify_code")):
                last_error_code = -2
                tcp_client.close()
                continue
            login_encryption_key = EncryptionKeyGenerator(
                password, login_prepare_data["salt"], login_prepare_data["verify_code"]
            ).generate()
            response_frames = tcp_client.send_message(
                LoginRequest(password, login_encryption_key.hex())
                .build_full_packet()
            )
            if len(response_frames) < 2:
                last_error_code = -3
                tcp_client.close()
                continue

            login_response = SystemResponse.from_packet(
                packet_receiver.decode_packet(response_frames[0].hex(), response_frames[1].hex())
            )
            if not login_response.is_success():
                last_error_code = login_response.result.code
                if last_error_code not in [-1, -2, -3, -6, 110]:
                    return {
                        "code": last_error_code,
                        "duration": round(time.time() - start_time, 2)
                    }
                tcp_client.close()
                continue
            login_data = packet_receiver.decrypt_login_reply_data(login_encryption_key.hex(), login_response.body["data"])
            uid = login_data.get("uid")
            session_key = login_data.get("session_key")
            if not session_key:
                last_error_code = -3
                tcp_client.close()
                continue
            response_frames = tcp_client.send_message(
                LoginTokenGetRequest(session_key).build_full_packet()
            )
            token_response = SystemResponse.from_packet(
                packet_receiver.decode_packet(response_frames[0].hex(), response_frames[1].hex(), session_key)
            )
            follow_up_packets = [
                EmptyPacket(session_key, command).build_full_packet()
                for command in (278, 511, 276, 278, 442, 342)
            ]
            tcp_client.connection_socket.sendall(b"".join(follow_up_packets))
            tcp_client.connection_socket.settimeout(0.5)

            replies_by_type = {}
            timeout_count = 0
            while timeout_count < 1:
                try:
                    frame_header = tcp_client.connection_socket.recv(4)
                    if not frame_header:
                        break
                    payload_length = struct.unpack("<I", frame_header)[0]
                    payload = tcp_client.receive_exactly(payload_length)
                    decoded_packet = packet_receiver.decode_packet(frame_header.hex(), payload.hex(), session_key)
                    message_type = decoded_packet.get("message_type", "UNKNOWN")
                    if message_type == "UNKNOWN":
                        continue
                    body = decoded_packet.get("body", {})
                    if message_type in replies_by_type:
                        if not isinstance(replies_by_type[message_type], list):
                            replies_by_type[message_type] = [replies_by_type[message_type]]
                        replies_by_type[message_type].append(body)
                    else:
                        replies_by_type[message_type] = body
                except socket.timeout:
                    timeout_count += 1
                    continue
                except Exception:
                    break
            sso_key = None
            if "SsoKeyGetReply" in replies_by_type:
                sso_data = replies_by_type["SsoKeyGetReply"]
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

        except Exception as error:
            last_error_code = -5
            print(f"[login] Exception on attempt {attempt}: {error}")
            if tcp_client:
                tcp_client.close()
            continue

        finally:
            if tcp_client:
                tcp_client.close()
    return {
        "code": last_error_code,
        "duration": round(time.time() - start_time, 2),
        "attempts": maximum_retries
    }


app = Flask(__name__)


@app.route('/api/login', methods=['GET'])
def handle_login_request():
    username = request.args.get('username')
    password = request.args.get('password')
    proxy = request.args.get('proxy')

    if not username or not password:
        return jsonify({"code": -1, "error": "Missing parameters"}), 400

    try:
        result = login_and_get_keys(username, password, proxy)
    except Exception as error:
        return jsonify({"code": -999, "error": str(error)}), 500

    return jsonify(result), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
