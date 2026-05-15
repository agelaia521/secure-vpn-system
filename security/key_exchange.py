"""
Diffie-Hellman 密钥交换模块
实现安全的密钥协商协议，允许双方在不安全信道上建立共享密钥
"""

import hashlib
import os


class DHKeyExchange:
    """
    Diffie-Hellman 密钥交换
    使用大素数和离散对数实现安全密钥协商
    """

    # 预定义的安全大素数和生成元 (RFC 3526 - 2048-bit MODP Group)
    # 简化版本使用较小的参数用于演示，实际应用应使用RFC标准参数
    PRIME = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
    )
    GENERATOR = 2

    def __init__(self, prime: int = None, generator: int = None):
        """
        初始化DH密钥交换
        :param prime: 大素数(可选，使用默认RFC 3526参数)
        :param generator: 生成元(可选)
        """
        self.prime = prime or self.PRIME
        self.generator = generator or self.GENERATOR
        self.private_key = None
        self.public_key = None

    def generate_key_pair(self) -> tuple:
        """
        生成DH密钥对
        :return: (public_key, private_key) 元组
        """
        # 生成随机私钥 (1 < private_key < prime-1)
        private_key = int.from_bytes(os.urandom(256), 'big') % (self.prime - 2) + 2
        # 计算公钥: g^private_key mod p
        public_key = pow(self.generator, private_key, self.prime)

        self.private_key = private_key
        self.public_key = public_key

        return public_key, private_key

    def compute_shared_secret(self, other_public_key: int) -> bytes:
        """
        计算共享密钥
        :param other_public_key: 对方的公钥
        :return: 共享密钥(32字节SHA-256哈希值)
        """
        if self.private_key is None:
            raise ValueError("未生成密钥对，请先调用 generate_key_pair()")

        # 计算共享密钥: other_public_key^private_key mod p
        shared_secret = pow(other_public_key, self.private_key, self.prime)

        # 使用SHA-256派生最终密钥
        shared_bytes = shared_secret.to_bytes(
            (shared_secret.bit_length() + 7) // 8, 'big'
        )
        derived_key = hashlib.sha256(shared_bytes).digest()

        return derived_key

    @classmethod
    def key_derivation(cls, shared_secret: bytes, context: str = "vpn-session") -> bytes:
        """
        从共享密钥派生多个子密钥
        :param shared_secret: 原始共享密钥
        :param context: 上下文标识
        :return: 派生密钥
        """
        # HKDF-like 密钥派生 (简化版)
        info = f"{context}-key-derivation".encode()
        h = hashlib.sha256()
        h.update(shared_secret + info)
        return h.digest()
