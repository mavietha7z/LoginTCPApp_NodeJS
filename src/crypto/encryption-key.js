import { createHash } from 'node:crypto';

/**
 * Sinh khóa XTEA 16 byte dùng cho bước Login (command 257).
 *
 * Tương ứng lớp `EncryptionKeyGenerator` trong `LoginTCPApp.py` (dòng 752–769).
 * Quy trình băm (phải giữ đúng thứ tự để máy chủ chấp nhận):
 *   1. passwordDigest = hex(MD5(utf8(password)))
 *   2. saltedDigest   = hex(SHA256(utf8(passwordDigest + salt)))
 *   3. khóa           = SHA256(utf8(saltedDigest + verifyCode)) lấy 16 byte đầu
 *
 * Không được thay MD5/SHA256 bằng thuật toán khác vì sẽ mất tương thích với giao thức.
 *
 * - `password` (string): Mật khẩu người dùng dạng chuỗi gốc.
 * - `salt` (string): Chuỗi salt máy chủ trả về trong LoginPrepareReply.
 * - `verifyCode` (string): Mã xác minh (verify_code) máy chủ trả về trong LoginPrepareReply.
 * - Trả về (Buffer): Khóa 16 byte dùng để mã hóa/giải mã dữ liệu bước Login.
 * - Ném lỗi TypeError: Khi một trong ba tham số không phải chuỗi.
 */
function generateEncryptionKey(password, salt, verifyCode) {
    const allParametersAreStrings = [password, salt, verifyCode].every((value) => typeof value === 'string');
    if (!allParametersAreStrings) {
        throw new TypeError('Mật khẩu, giá trị salt và mã xác minh phải là các chuỗi ký tự');
    }

    /*
     * Bước 1: băm MD5 mật khẩu, lấy dạng chuỗi hex.
     */
    const passwordDigest = createHash('md5').update(password, 'utf8').digest('hex');

    /*
     * Bước 2: nối salt rồi băm SHA256, lấy dạng chuỗi hex.
     */
    const saltedDigest = createHash('sha256')
        .update(passwordDigest + salt, 'utf8')
        .digest('hex');

    /*
     * Bước 3: nối verifyCode rồi băm SHA256, chỉ giữ 16 byte đầu làm khóa XTEA.
     */
    return createHash('sha256')
        .update(saltedDigest + verifyCode, 'utf8')
        .digest()
        .subarray(0, 16);
}

export { generateEncryptionKey };
