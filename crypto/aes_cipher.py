"""
AES 对称加密模块（增强版）
实现 AES-256-CBC / AES-256-GCM 双模式加密，支持PKCS7填充
AES-GCM 提供认证加密（AEAD），同时保证机密性和完整性
"""

import os
import base64
import struct
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, aead
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class AESCipher:
    """AES 对称加密器，支持 CBC 和 GCM 两种模式"""

    def __init__(self, key_size: int = 32):
        self.key_size = key_size
        self.block_size = algorithms.AES.block_size // 8  # 16 bytes

    def generate_key(self) -> bytes:
        """生成随机AES密钥"""
        return os.urandom(self.key_size)

    def generate_iv(self) -> bytes:
        """生成随机初始化向量(IV/Nonce)"""
        return os.urandom(self.block_size)

    def generate_nonce(self) -> bytes:
        """生成GCM模式所需的Nonce(12字节)"""
        return os.urandom(12)

    # ==================== CBC 模式 ====================

    def _pkcs7_pad(self, data: bytes) -> bytes:
        padder = padding.PKCS7(self.block_size * 8).padder()
        return padder.update(data) + padder.finalize()

    def _pkcs7_unpad(self, data: bytes) -> bytes:
        unpadder = padding.PKCS7(self.block_size * 8).unpadder()
        return unpadder.update(data) + unpadder.finalize()

    def encrypt_cbc(self, plaintext: str, key: bytes, iv: bytes = None) -> str:
        """AES-256-CBC 加密"""
        if iv is None:
            iv = self.generate_iv()
        data = plaintext.encode('utf-8')
        padded_data = self._pkcs7_pad(data)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        ciphertext = cipher.encryptor().update(padded_data) + cipher.encryptor().finalize()
        # 格式: MODE(1B) + IV(16B) + ciphertext
        combined = b'\x01' + iv + ciphertext
        return base64.b64encode(combined).decode('utf-8')

    def decrypt_cbc(self, ciphertext_b64: str, key: bytes) -> str:
        """AES-256-CBC 解密"""
        combined = base64.b64decode(ciphertext_b64)
        mode_byte = combined[0:1]
        iv = combined[1:1 + self.block_size]
        ciphertext = combined[1 + self.block_size:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        data = self._pkcs7_unpad(padded_data)
        return data.decode('utf-8')

    # ==================== GCM 模式（认证加密 AEAD）====================

    def encrypt_gcm(self, plaintext: str, key: bytes, aad: bytes = None, nonce: bytes = None) -> str:
        """
        AES-256-GCM 认证加密
        GCM模式同时提供加密和认证，无需额外HMAC
        :param plaintext: 明文
        :param key: 加密密钥
        :param aad: 附加认证数据（Additional Authenticated Data），不加密但受认证保护
        :param nonce: Nonce(12字节)，自动生成
        :return: Base64编码密文 (格式: MODE(1B) + Nonce(12B) + Tag(16B) + Ciphertext)
        """
        if nonce is None:
            nonce = self.generate_nonce()
        if aad is None:
            aad = b''

        data = plaintext.encode('utf-8')
        aesgcm = aead.AESGCM(key)
        # encrypt返回 ciphertext + tag(16B) 拼接
        ct_and_tag = aesgcm.encrypt(nonce, data, aad)
        ciphertext = ct_and_tag[:-16]
        tag = ct_and_tag[-16:]

        # 格式: MODE(1B) + Nonce(12B) + Tag(16B) + Ciphertext
        combined = b'\x02' + nonce + tag + ciphertext
        return base64.b64encode(combined).decode('utf-8')

    def decrypt_gcm(self, ciphertext_b64: str, key: bytes, aad: bytes = None) -> str:
        """
        AES-256-GCM 认证解密
        如果数据被篡改，将自动抛出 InvalidTag 异常
        """
        if aad is None:
            aad = b''
        combined = base64.b64decode(ciphertext_b64)
        nonce = combined[1:13]       # 12 bytes
        tag = combined[13:29]        # 16 bytes
        ciphertext = combined[29:]   # rest

        aesgcm = aead.AESGCM(key)
        ct_and_tag = ciphertext + tag
        plaintext = aesgcm.decrypt(nonce, ct_and_tag, aad)
        return plaintext.decode('utf-8')

    # ==================== 通用接口（默认GCM）====================

    def encrypt(self, plaintext: str, key: bytes, iv: bytes = None) -> str:
        """默认使用GCM模式加密"""
        return self.encrypt_gcm(plaintext, key, nonce=iv)

    def decrypt(self, ciphertext_b64: str, key: bytes) -> str:
        """自动识别模式解密"""
        combined = base64.b64decode(ciphertext_b64)
        mode_byte = combined[0:1]
        if mode_byte == b'\x01':
            return self.decrypt_cbc(ciphertext_b64, key)
        elif mode_byte == b'\x02':
            return self.decrypt_gcm(ciphertext_b64, key)
        else:
            raise ValueError(f"未知的加密模式标识: {mode_byte}")

    def encrypt_bytes(self, data: bytes, key: bytes, iv: bytes = None) -> bytes:
        """加密字节数据（CBC模式）"""
        if iv is None:
            iv = self.generate_iv()
        padded_data = self._pkcs7_pad(data)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext

    def decrypt_bytes(self, combined: bytes, key: bytes) -> bytes:
        """解密字节数据（CBC模式）"""
        iv = combined[:self.block_size]
        ciphertext = combined[self.block_size:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        return self._pkcs7_unpad(padded_data)


# ==================== 密钥派生函数 ====================

class KeyDerivation:
    """
    密钥派生模块
    支持 HKDF (HMAC-based Extract-and-Expand Key Derivation Function)
    和 PBKDF2 (Password-Based Key Derivation Function 2)
    """

    @staticmethod
    def hkdf_derive(master_key: bytes, info: bytes = b"", length: int = 32,
                     salt: bytes = None, hash_algorithm=hashes.SHA256()) -> bytes:
        """
        HKDF 密钥派生
        从主密钥派生出指定长度的子密钥
        :param master_key: 主密钥/输入密钥材料
        :param info: 上下文信息
        :param length: 输出密钥长度
        :param salt: 盐值(可选)
        :param hash_algorithm: 哈希算法
        :return: 派生密钥
        """
        hkdf = HKDF(
            algorithm=hash_algorithm,
            length=length,
            salt=salt,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(master_key)

    @staticmethod
    def hkdf_derive_multiple(master_key: bytes, info_prefix: str = "vpn",
                              lengths: dict = None) -> dict:
        """
        从一个主密钥派生多个子密钥
        :param master_key: 主密钥
        :param info_prefix: 信息前缀
        :param lengths: 各子密钥长度，如 {"enc": 32, "mac": 32, "iv": 16}
        :return: 子密钥字典
        """
        if lengths is None:
            lengths = {"encryption": 32, "hmac": 32, "iv": 16}

        keys = {}
        for name, length in lengths.items():
            info = f"{info_prefix}-{name}".encode()
            keys[name] = KeyDerivation.hkdf_derive(master_key, info, length)
        return keys

    @staticmethod
    def pbkdf2_derive(password: str, salt: bytes = None, iterations: int = 600000,
                      key_length: int = 32, hash_algorithm=hashes.SHA256()) -> tuple:
        """
        PBKDF2 密码派生密钥
        从用户密码安全地派生加密密钥
        :param password: 用户密码
        :param salt: 盐值(自动生成)
        :param iterations: 迭代次数(OWASP推荐600000+)
        :param key_length: 输出密钥长度
        :param hash_algorithm: 哈希算法
        :return: (derived_key, salt) 元组
        """
        if salt is None:
            salt = os.urandom(16)

        if isinstance(password, str):
            password = password.encode('utf-8')

        kdf = PBKDF2HMAC(
            algorithm=hash_algorithm,
            length=key_length,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password)
        return key, salt

    @staticmethod
    def derive_session_keys(shared_secret: bytes) -> dict:
        """
        从DH共享密钥派生完整的会话密钥集
        模拟TLS 1.3的密钥派生流程
        :param shared_secret: DH交换得到的共享密钥
        :return: 包含所有会话密钥的字典
        """
        # 使用HKDF-Extract生成中间密钥
        salt = b"SecureVPN-handshake-salt"
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=96,  # 32 + 32 + 16 + 16
            salt=salt,
            info=b"SecureVPN session key derivation",
            backend=default_backend()
        )
        expanded = hkdf.derive(shared_secret)

        return {
            "client_write_key": expanded[0:32],    # 客户端写入加密密钥
            "server_write_key": expanded[32:64],    # 服务端写入加密密钥
            "client_write_iv": expanded[64:80],     # 客户端写入IV
            "server_write_iv": expanded[80:96],     # 服务端写入IV
        }
