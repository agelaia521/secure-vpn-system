"""
数字签名模块
实现 RSA-PSS 数字签名，支持签名生成与验证
"""

import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.backends import default_backend


class DigitalSignature:
    """RSA-PSS 数字签名器"""

    def __init__(self, key_size: int = 2048):
        """
        初始化数字签名器
        :param key_size: RSA密钥长度
        """
        self.key_size = key_size

    def generate_key_pair(self) -> dict:
        """
        生成用于签名的RSA密钥对
        :return: 包含private_key和public_key的字典
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

    def sign(self, data: str, private_key) -> str:
        """
        对数据进行数字签名
        :param data: 待签名的数据字符串
        :param private_key: RSA私钥
        :return: Base64编码的签名值
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    def sign_bytes(self, data: bytes, private_key) -> bytes:
        """
        对字节数据进行数字签名
        :param data: 待签名的数据字节
        :param private_key: RSA私钥
        :return: 签名值字节
        """
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify(self, data: str, signature_b64: str, public_key) -> bool:
        """
        验证数字签名
        :param data: 原始数据字符串
        :param signature_b64: Base64编码的签名值
        :param public_key: RSA公钥
        :return: 验证结果(True=有效, False=无效或被篡改)
        """
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            signature = base64.b64decode(signature_b64)

            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def verify_bytes(self, data: bytes, signature: bytes, public_key) -> bool:
        """
        验证字节数据的数字签名
        :param data: 原始数据字节
        :param signature: 签名值字节
        :param public_key: RSA公钥
        :return: 验证结果
        """
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
