"""
VPN 配置管理模块
集中管理VPN系统的各项配置参数
"""


class VPNConfig:
    """VPN系统配置"""

    def __init__(self):
        # 网络配置
        self.server_host = "0.0.0.0"
        self.server_port = 9090

        # 加密配置
        self.aes_key_size = 32          # AES-256
        self.rsa_key_size = 2048        # RSA-2048
        self.dh_group_size = 2048       # DH组大小

        # 隧道配置
        self.tunnel_mtu = 1400          # 隧道MTU
        self.tunnel_timeout = 30        # 隧道超时(秒)
        self.max_retries = 3            # 最大重试次数

        # 会话配置
        self.session_timeout = 3600     # 会话超时(秒)
        self.max_sessions = 100         # 最大会话数

        # 证书配置
        self.cert_validity_days = 365   # 证书有效期(天)
        self.ca_name = "SecureVPN-CA"   # CA名称

        # 日志配置
        self.log_level = "INFO"
        self.log_file = None

    def to_dict(self) -> dict:
        """导出配置为字典"""
        return {
            "server_host": self.server_host,
            "server_port": self.server_port,
            "aes_key_size": self.aes_key_size,
            "rsa_key_size": self.rsa_key_size,
            "dh_group_size": self.dh_group_size,
            "tunnel_mtu": self.tunnel_mtu,
            "tunnel_timeout": self.tunnel_timeout,
            "session_timeout": self.session_timeout,
            "max_sessions": self.max_sessions,
            "cert_validity_days": self.cert_validity_days,
            "ca_name": self.ca_name,
        }

    def __repr__(self) -> str:
        return f"VPNConfig(host={self.server_host}, port={self.server_port})"
