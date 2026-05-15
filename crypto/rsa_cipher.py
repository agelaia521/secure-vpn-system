"""
RSA 非对称加密模块
实现 RSA-2048 OAEP 加密/解密，支持密钥对生成与PEM格式导入导出
"""

import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


class RSACipher:
    """RSA 非对称加密器"""

    def __init__(self, key_size: int = 2048):
        """
        初始化RSA加密器
        :param key_size: 密钥长度(位)，推荐2048或4096
        """
        self.key_size = key_size

    def generate_key_pair(self) -> dict:
        """
        生成RSA密钥对
        :return: 包含public_key和private_key的字典
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return {
            "private_key": private_key,
            "public_key": public_key
        }

    def export_public_key_pem(self, public_key) -> str:
        """
        导出PEM格式公钥
        :param public_key: RSA公钥对象
        :return: PEM格式字符串
        """
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')

    def export_private_key_pem(self, private_key, password: bytes = None) -> str:
        """
        导出PEM格式私钥
        :param private_key: RSA私钥对象
        :param password: 加密密码(可选)
        :return: PEM格式字符串
        """
        encryption = (serialization.NoEncryption()
                      if password is None
                      else serialization.BestAvailableEncryption(password))
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        return pem.decode('utf-8')

    def import_public_key_pem(self, pem_str: str):
        """
        从PEM字符串导入公钥
        :param pem_str: PEM格式公钥字符串
        :return: RSA公钥对象
        """
        public_key = serialization.load_pem_public_key(
            pem_str.encode('utf-8'),
            backend=default_backend()
        )
        return public_key

    def import_private_key_pem(self, pem_str: str, password: bytes = None):
        """
        从PEM字符串导入私钥
        :param pem_str: PEM格式私钥字符串
        :param password: 解密密码(可选)
        :return: RSA私钥对象
        """
        private_key = serialization.load_pem_private_key(
            pem_str.encode('utf-8'),
            password=password,
            backend=default_backend()
        )
        return private_key

    def encrypt(self, plaintext: str, public_key) -> str:
        """
        RSA-OAEP 加密
        :param plaintext: 明文字符串
        :param public_key: RSA公钥
        :return: Base64编码的密文
        """
        data = plaintext.encode('utf-8')
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode('utf-8')

    def decrypt(self, ciphertext_b64: str, private_key) -> str:
        """
        RSA-OAEP 解密
        :param ciphertext_b64: Base64编码的密文
        :param private_key: RSA私钥
        :return: 解密后的明文字符串
        """
        ciphertext = base64.b64decode(ciphertext_b64)
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf-8')

    def encrypt_bytes(self, data: bytes, public_key) -> bytes:
        """
        RSA-OAEP 加密字节数据
        :param data: 明文字节
        :param public_key: RSA公钥
        :return: 密文字节
        """
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt_bytes(self, ciphertext: bytes, private_key) -> bytes:
        """
        RSA-OAEP 解密字节数据
        :param ciphertext: 密文字节
        :param private_key: RSA私钥
        :return: 明文字节
        """
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
