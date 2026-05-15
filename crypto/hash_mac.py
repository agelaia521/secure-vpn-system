"""
SHA-256 哈希与 HMAC 消息认证码模块
提供数据摘要、HMAC生成与验证功能
"""

import os
import hmac
import hashlib
import base64


class HashMAC:
    """SHA-256 哈希与 HMAC-SHA256 消息认证码"""

    def __init__(self, hash_algorithm: str = "sha256"):
        """
        初始化哈希模块
        :param hash_algorithm: 哈希算法名称 (sha256, sha384, sha512)
        """
        self.hash_algorithm = hash_algorithm

    def sha256_hash(self, data: str) -> str:
        """
        计算数据的SHA-256哈希值
        :param data: 输入字符串
        :return: 十六进制哈希值
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).hexdigest()

    def sha256_hash_bytes(self, data: bytes) -> bytes:
        """
        计算字节数据的SHA-256哈希值
        :param data: 输入字节
        :return: 哈希值字节
        """
        return hashlib.sha256(data).digest()

    def generate_hmac_key(self, key_size: int = 32) -> bytes:
        """
        生成HMAC密钥
        :param key_size: 密钥长度(字节)
        :return: 随机密钥
        """
        return os.urandom(key_size)

    def hmac_generate(self, data: str, key: bytes) -> str:
        """
        生成HMAC-SHA256消息认证码
        :param data: 待认证数据
        :param key: HMAC密钥
        :return: 十六进制HMAC值
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        h = hmac.new(key, data, hashlib.sha256)
        return h.hexdigest()

    def hmac_generate_bytes(self, data: bytes, key: bytes) -> bytes:
        """
        生成HMAC-SHA256消息认证码(字节)
        :param data: 待认证数据
        :param key: HMAC密钥
        :return: HMAC值字节
        """
        h = hmac.new(key, data, hashlib.sha256)
        return h.digest()

    def hmac_verify(self, data: str, hmac_hex: str, key: bytes) -> bool:
        """
        验证HMAC-SHA256消息认证码
        :param data: 待验证数据
        :param hmac_hex: 十六进制HMAC值
        :param key: HMAC密钥
        :return: 验证结果(True/False)
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        expected = hmac.new(key, data, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, hmac_hex)

    def hmac_verify_bytes(self, data: bytes, hmac_digest: bytes, key: bytes) -> bool:
        """
        验证HMAC-SHA256消息认证码(字节)
        :param data: 待验证数据
        :param hmac_digest: HMAC值字节
        :param key: HMAC密钥
        :return: 验证结果(True/False)
        """
        expected = hmac.new(key, data, hashlib.sha256).digest()
        return hmac.compare_digest(expected, hmac_digest)

    def multi_hash(self, data: str) -> dict:
        """
        计算多种哈希值
        :param data: 输入字符串
        :return: 包含多种哈希值的字典
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        return {
            "MD5": hashlib.md5(data).hexdigest(),
            "SHA-1": hashlib.sha1(data).hexdigest(),
            "SHA-256": hashlib.sha256(data).hexdigest(),
            "SHA-384": hashlib.sha384(data).hexdigest(),
            "SHA-512": hashlib.sha512(data).hexdigest(),
        }
