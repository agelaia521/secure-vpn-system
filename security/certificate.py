"""
数字证书模块（增强版）
实现简化的X.509数字证书系统，包含CA证书颁发、验证、吊销和CRL
"""

import os
import json
import hashlib
import time
import copy
from typing import Optional, List


class CertificateAuthority:
    """
    证书颁发机构 (CA)
    负责签发和管理数字证书，支持CRL证书吊销列表
    """

    def __init__(self, ca_name: str = "SecureVPN-CA", country: str = "CN"):
        self.ca_name = ca_name
        self.country = country
        self.serial_counter = 1000
        self.ca_public_key_hash = hashlib.sha256(
            f"{ca_name}-{country}-{time.time()}".encode()
        ).hexdigest()[:32]
        self.issued_certificates = {}
        self.crl = CertificateRevocationList(self.ca_name)

    def _next_serial(self) -> int:
        self.serial_counter += 1
        return self.serial_counter

    def issue_certificate(
        self,
        subject: str,
        subject_info: dict = None,
        validity_days: int = 365
    ) -> dict:
        """签发数字证书"""
        now = time.time()
        serial = self._next_serial()

        certificate = {
            "version": "X.509v3",
            "serial_number": f"SN-{serial:08d}",
            "issuer": {
                "common_name": self.ca_name,
                "country": self.country,
                "organization": "SecureVPN Certificate Authority"
            },
            "subject": subject,
            "subject_info": subject_info or {},
            "validity": {
                "not_before": now,
                "not_after": now + validity_days * 86400,
                "days": validity_days
            },
            "public_key_algorithm": "RSA-2048",
            "signature_algorithm": "RSA-PSS-SHA256",
            "ca_public_key_hash": self.ca_public_key_hash,
            "fingerprint": hashlib.sha256(
                f"{subject}-{serial}-{now}".encode()
            ).hexdigest(),
            "extensions": {
                "basic_constraints": {"ca": False},
                "key_usage": [
                    "digital_signature",
                    "key_encipherment",
                    "data_encipherment"
                ],
                "extended_key_usage": [
                    "server_auth",
                    "client_auth"
                ]
            },
            "revoked": False
        }

        cert_data = json.dumps(certificate, sort_keys=True, default=str)
        cert_hash = hashlib.sha256(cert_data.encode()).hexdigest()
        certificate["ca_signature"] = hashlib.sha256(
            (cert_hash + self.ca_public_key_hash).encode()
        ).hexdigest()

        self.issued_certificates[certificate["serial_number"]] = certificate
        return certificate

    def verify_certificate(self, certificate: dict) -> dict:
        """
        增强版证书验证，返回详细的验证结果
        :return: {"valid": bool, "details": dict}
        """
        result = {"valid": True, "details": {}}

        try:
            # 1. 检查CA签名
            cert_copy = copy.deepcopy(certificate)
            original_sig = cert_copy.pop("ca_signature", None)
            if original_sig is None:
                result["valid"] = False
                result["details"]["signature"] = "缺少CA签名"
                return result

            cert_data = json.dumps(cert_copy, sort_keys=True, default=str)
            cert_hash = hashlib.sha256(cert_data.encode()).hexdigest()
            expected_sig = hashlib.sha256(
                (cert_hash + self.ca_public_key_hash).encode()
            ).hexdigest()

            if not _safe_compare(original_sig, expected_sig):
                result["valid"] = False
                result["details"]["signature"] = "CA签名验证失败（证书可能被篡改）"
            else:
                result["details"]["signature"] = "CA签名验证通过"

            # 2. 检查有效期
            now = time.time()
            not_before = certificate.get("validity", {}).get("not_before", 0)
            not_after = certificate.get("validity", {}).get("not_after", 0)

            if now < not_before:
                result["valid"] = False
                result["details"]["validity"] = "证书尚未生效"
            elif now > not_after:
                result["valid"] = False
                result["details"]["validity"] = "证书已过期"
            else:
                remaining = (not_after - now) / 86400
                result["details"]["validity"] = f"证书有效（剩余{remaining:.1f}天）"

            # 3. 检查CA公钥哈希
            if certificate.get("ca_public_key_hash") != self.ca_public_key_hash:
                result["valid"] = False
                result["details"]["issuer"] = "证书签发者不匹配"
            else:
                result["details"]["issuer"] = "签发者验证通过"

            # 4. 检查序列号
            serial = certificate.get("serial_number")
            if serial not in self.issued_certificates:
                result["valid"] = False
                result["details"]["serial"] = "序列号不在已签发列表中"
            else:
                result["details"]["serial"] = "序列号验证通过"

            # 5. 检查CRL吊销列表
            if self.crl.is_revoked(serial):
                entry = self.crl.get_revocation_entry(serial)
                result["valid"] = False
                result["details"]["revocation"] = f"证书已被吊销（原因: {entry['reason']}，时间: {entry['revocation_date']}）"
            else:
                result["details"]["revocation"] = "证书未被吊销"

        except Exception as e:
            result["valid"] = False
            result["details"]["error"] = str(e)

        return result

    def revoke_certificate(self, serial_number: str, reason: str = "unspecified") -> bool:
        """
        吊销证书并添加到CRL
        :param serial_number: 证书序列号
        :param reason: 吊销原因
        """
        if serial_number in self.issued_certificates:
            self.issued_certificates[serial_number]["revoked"] = True
            self.crl.add_revocation(serial_number, reason)
            return True
        return False

    def is_revoked(self, serial_number: str) -> bool:
        """检查证书是否被吊销"""
        return self.crl.is_revoked(serial_number)

    def get_crl_info(self) -> str:
        """获取CRL信息"""
        return self.crl.to_string()

    def get_certificate_info(self, certificate: dict) -> str:
        """获取证书信息摘要"""
        validity = certificate.get("validity", {})
        not_before = time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(validity.get("not_before", 0))
        )
        not_after = time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(validity.get("not_after", 0))
        )
        status = "已吊销" if certificate.get("revoked") else "有效"

        return (
            f"版本: {certificate.get('version', 'N/A')}  |  "
            f"序列号: {certificate.get('serial_number', 'N/A')}  |  "
            f"签发者: {certificate.get('issuer', {}).get('common_name', 'N/A')}  |  "
            f"主题: {certificate.get('subject', 'N/A')}  |  "
            f"有效期: {not_before} ~ {not_after}  |  "
            f"状态: {status}  |  "
            f"签名算法: {certificate.get('signature_algorithm', 'N/A')}  |  "
            f"指纹: {certificate.get('fingerprint', 'N/A')}"
        )


class CertificateRevocationList:
    """
    证书吊销列表 (CRL - Certificate Revocation List)
    管理所有已吊销的证书
    """

    def __init__(self, issuer_name: str):
        self.issuer_name = issuer_name
        self.revoked_certs = {}  # {serial_number: {reason, date, serial}}
        self.created_at = time.time()
        self.last_updated = time.time()
        self.next_update = time.time() + 86400  # CRL自身有效期1天

    def add_revocation(self, serial_number: str, reason: str = "unspecified"):
        """
        添加吊销条目
        :param serial_number: 被吊销的证书序列号
        :param reason: 吊销原因 (unspecified/key_compromise/ca_compromise/superseded/cessation_of_operation)
        """
        reason_map = {
            "unspecified": "未指定",
            "key_compromise": "密钥泄露",
            "ca_compromise": "CA泄露",
            "superseded": "已被替代",
            "cessation_of_operation": "停止运营",
            "privilege_withdrawn": "权限撤销",
            "aa_compromise": "AA泄露"
        }

        self.revoked_certs[serial_number] = {
            "serial_number": serial_number,
            "revocation_date": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "reason": reason_map.get(reason, reason),
            "reason_code": reason
        }
        self.last_updated = time.time()

    def is_revoked(self, serial_number: str) -> bool:
        """检查证书是否在吊销列表中"""
        return serial_number in self.revoked_certs

    def get_revocation_entry(self, serial_number: str) -> Optional[dict]:
        """获取吊销条目详情"""
        return self.revoked_certs.get(serial_number)

    def remove_revocation(self, serial_number: str) -> bool:
        """从CRL中移除吊销条目（仅用于测试）"""
        if serial_number in self.revoked_certs:
            del self.revoked_certs[serial_number]
            self.last_updated = time.time()
            return True
        return False

    def get_revoked_count(self) -> int:
        """获取已吊销证书数量"""
        return len(self.revoked_certs)

    def is_crl_valid(self) -> bool:
        """检查CRL自身是否在有效期内"""
        return time.time() < self.next_update

    def to_string(self) -> str:
        """格式化输出CRL信息"""
        lines = [
            f"证书吊销列表 (CRL)",
            f"签发者: {self.issuer_name}",
            f"创建时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.created_at))}",
            f"最后更新: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.last_updated))}",
            f"下次更新: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.next_update))}",
            f"CRL状态: {'有效' if self.is_crl_valid() else '已过期'}",
            f"已吊销证书数: {self.get_revoked_count()}",
            "-" * 60
        ]
        for serial, entry in self.revoked_certs.items():
            lines.append(
                f"  序列号: {serial}  |  吊销时间: {entry['revocation_date']}  |  原因: {entry['reason']}"
            )
        return "\n".join(lines)


def _safe_compare(a: str, b: str) -> bool:
    """安全字符串比较(防止时序攻击)"""
    import hmac as hmac_mod
    return hmac_mod.compare_digest(a.encode(), b.encode())
