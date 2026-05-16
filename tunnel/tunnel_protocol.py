"""
VPN隧道协议模块（增强版）
实现自定义隧道协议封装/解封装，支持AES-GCM认证加密、数据压缩、心跳保活、连接统计
"""

import os
import json
import time
import zlib
import hashlib
import hmac as hmac_mod
import threading
from typing import Optional

from crypto.aes_cipher import AESCipher
from crypto.hash_mac import HashMAC
from security.integrity import AntiReplayWindow, SessionKeyManager


class ConnectionStats:
    """连接统计器"""

    def __init__(self):
        self.start_time = time.time()
        self.bytes_sent = 0
        self.bytes_received = 0
        self.packets_sent = 0
        self.packets_received = 0
        self.packets_encrypted = 0
        self.packets_decrypted = 0
        self.compression_ratio = 0.0
        self.compression_saved = 0
        self.lock = threading.Lock()

    def record_sent(self, original_size: int, compressed_size: int = 0):
        with self.lock:
            self.packets_sent += 1
            self.bytes_sent += original_size
            self.packets_encrypted += 1
            if compressed_size > 0 and original_size > 0:
                saved = original_size - compressed_size
                self.compression_saved += saved

    def record_received(self, size: int):
        with self.lock:
            self.packets_received += 1
            self.bytes_received += size
            self.packets_decrypted += 1

    def get_stats(self) -> dict:
        with self.lock:
            duration = time.time() - self.start_time
            total = self.bytes_sent + self.bytes_received
            ratio = (self.compression_saved / max(1, self.bytes_sent)) * 100 if self.bytes_sent > 0 else 0
            return {
                "duration_seconds": int(duration),
                "bytes_sent": self.bytes_sent,
                "bytes_received": self.bytes_received,
                "total_bytes": total,
                "packets_sent": self.packets_sent,
                "packets_received": self.packets_received,
                "packets_encrypted": self.packets_encrypted,
                "packets_decrypted": self.packets_decrypted,
                "compression_saved_bytes": self.compression_saved,
                "compression_ratio": f"{ratio:.1f}%",
                "avg_throughput_bps": int(total / max(1, duration))
            }


class HeartbeatMonitor:
    """
    心跳保活监控器
    定期发送心跳包检测连接活性，超时自动断开
    """

    def __init__(self, interval: int = 30, timeout: int = 90):
        """
        :param interval: 心跳间隔(秒)
        :param timeout: 超时时间(秒)，超过此时间未收到心跳则判定连接断开
        """
        self.interval = interval
        self.timeout = timeout
        self.last_heartbeat_sent = time.time()
        self.last_heartbeat_received = time.time()
        self.heartbeat_count = 0
        self.timeout_count = 0
        self.is_alive = True
        self.lock = threading.Lock()

    def send_heartbeat(self) -> dict:
        """生成心跳包"""
        with self.lock:
            self.last_heartbeat_sent = time.time()
            self.heartbeat_count += 1
            return {
                "type": "HEARTBEAT",
                "timestamp": self.last_heartbeat_sent,
                "sequence": self.heartbeat_count,
                "payload": os.urandom(16).hex()  # 随机载荷防止重放
            }

    def receive_heartbeat(self, heartbeat: dict) -> bool:
        """处理收到的心跳包"""
        with self.lock:
            self.last_heartbeat_received = time.time()
            self.is_alive = True
            return True

    def check_alive(self) -> bool:
        """检查连接是否存活"""
        with self.lock:
            elapsed = time.time() - self.last_heartbeat_received
            if elapsed > self.timeout:
                self.is_alive = False
                self.timeout_count += 1
                return False
            return True

    def should_send_heartbeat(self) -> bool:
        """检查是否需要发送心跳"""
        with self.lock:
            return (time.time() - self.last_heartbeat_sent) >= self.interval

    def get_status(self) -> dict:
        """获取心跳状态"""
        with self.lock:
            return {
                "is_alive": self.is_alive,
                "interval": self.interval,
                "timeout": self.timeout,
                "last_sent": time.strftime("%H:%M:%S", time.localtime(self.last_heartbeat_sent)),
                "last_received": time.strftime("%H:%M:%S", time.localtime(self.last_heartbeat_received)),
                "heartbeat_count": self.heartbeat_count,
                "timeout_count": self.timeout_count,
                "seconds_since_last_received": int(time.time() - self.last_heartbeat_received)
            }


class TunnelProtocol:
    """
    VPN隧道协议（增强版）
    
    协议格式:
    ┌──────────────────────────────────────────────┐
    │ 隧道头部 (Tunnel Header)                      │
    │  - 版本号 (1 byte)                            │
    │  - 加密模式 (1 byte): CBC=1, GCM=2           │
    │  - 协议类型 (1 byte): TCP=1, UDP=2, ICMP=3    │
    │  - 标志位 (1 byte): 加密|压缩|签名|心跳       │
    │  - 密钥版本 (2 bytes)                         │
    │  - 序列号 (4 bytes)                           │
    │  - 源IP / 目的IP (variable)                   │
    │  - 时间戳 (8 bytes)                           │
    ├──────────────────────────────────────────────┤
    │ 加密载荷 (Encrypted Payload)                  │
    │  - AES-256-GCM 或 AES-256-CBC 加密           │
    ├──────────────────────────────────────────────┤
    │ HMAC标签 (HMAC Tag, 32 bytes, CBC模式)        │
    └──────────────────────────────────────────────┘
    """

    PROTOCOL_VERSION = 2
    ENCRYPT_MODES = {"CBC": 1, "GCM": 2}
    PROTOCOL_TYPES = {"TCP": 1, "UDP": 2, "ICMP": 3, "CUSTOM": 4}
    FLAGS = {"ENCRYPTED": 1, "COMPRESSED": 2, "SIGNED": 4, "HEARTBEAT": 8}

    def __init__(self, encrypt_mode: str = "GCM", enable_compression: bool = True):
        self.aes = AESCipher()
        self.hash_mac = HashMAC()
        self.sequence_counter = 0
        self.encrypt_mode = encrypt_mode
        self.enable_compression = enable_compression
        self.stats = ConnectionStats()
        self.heartbeat = HeartbeatMonitor()
        self.anti_replay = AntiReplayWindow()
        self.key_manager = SessionKeyManager()

    def _next_sequence(self) -> int:
        self.sequence_counter += 1
        return self.sequence_counter

    def _compress(self, data: str) -> tuple:
        """压缩数据"""
        if not self.enable_compression:
            return data, False
        try:
            data_bytes = data.encode('utf-8')
            compressed = zlib.compress(data_bytes, level=6)
            ratio = len(compressed) / len(data_bytes)
            if ratio < 0.95:  # 压缩后小于95%才使用压缩
                return compressed.decode('latin-1'), True
            return data, False
        except Exception:
            return data, False

    def _decompress(self, data: str) -> str:
        """解压数据"""
        try:
            return zlib.decompress(data.encode('latin-1')).decode('utf-8')
        except Exception:
            return data

    def encapsulate(
        self,
        payload: str,
        src_ip: str = "0.0.0.0",
        dst_ip: str = "0.0.0.0",
        protocol: str = "TCP",
        session_key: bytes = None,
        hmac_key: bytes = None
    ) -> dict:
        """封装数据包到VPN隧道（增强版）"""
        if hmac_key is None:
            hmac_key = session_key or os.urandom(32)

        sequence = self._next_sequence()
        timestamp = time.time()

        # 压缩
        processed_payload, compressed = self._compress(payload)

        # 加密
        mode_code = self.ENCRYPT_MODES.get(self.encrypt_mode, 2)
        if session_key:
            if self.encrypt_mode == "GCM":
                aad = json.dumps({"seq": sequence, "src": src_ip, "dst": dst_ip}).encode()
                encrypted_payload = self.aes.encrypt_gcm(processed_payload, session_key, aad=aad)
            else:
                encrypted_payload = self.aes.encrypt_cbc(processed_payload, session_key)
        else:
            encrypted_payload = processed_payload

        # 构建头部
        flags = self.FLAGS["ENCRYPTED"] | self.FLAGS["SIGNED"]
        if compressed:
            flags |= self.FLAGS["COMPRESSED"]

        header = {
            "version": self.PROTOCOL_VERSION,
            "encrypt_mode": self.encrypt_mode,
            "encrypt_mode_code": mode_code,
            "protocol": protocol,
            "protocol_code": self.PROTOCOL_TYPES.get(protocol, 4),
            "flags": flags,
            "key_version": self.key_manager.key_version,
            "sequence": sequence,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "timestamp": timestamp,
            "payload_length": len(payload.encode('utf-8')),
            "compressed": compressed,
            "compression_ratio": f"{len(encrypted_payload) / max(1, len(payload.encode('utf-8'))) * 100:.1f}%"
        }

        # HMAC完整性标签
        header_bytes = json.dumps(header, sort_keys=True).encode('utf-8')
        payload_bytes = encrypted_payload.encode('utf-8') if isinstance(encrypted_payload, str) else encrypted_payload
        hmac_data = header_bytes + payload_bytes
        hmac_tag = hmac_mod.new(hmac_key, hmac_data, hashlib.sha256).hexdigest()

        # 统计
        self.stats.record_sent(len(payload.encode('utf-8')), len(encrypted_payload) if isinstance(encrypted_payload, str) else len(encrypted_payload))

        return {
            "header": header,
            "encrypted_payload": encrypted_payload,
            "hmac_tag": hmac_tag
        }

    def decapsulate(self, packet: dict, session_key: bytes = None, hmac_key: bytes = None) -> str:
        """从VPN隧道解封装数据包（增强版）"""
        if hmac_key is None:
            hmac_key = session_key or os.urandom(32)

        header = packet["header"]
        encrypted_payload = packet["encrypted_payload"]
        stored_hmac = packet["hmac_tag"]

        # 防重放检查
        replay_check = self.anti_replay.check_and_update(
            header.get("sequence", 0),
            header.get("timestamp")
        )
        if not replay_check["accepted"]:
            raise ValueError(f"防重放检查失败: {replay_check['reason']}")

        # HMAC完整性验证
        header_bytes = json.dumps(header, sort_keys=True).encode('utf-8')
        payload_bytes = encrypted_payload.encode('utf-8') if isinstance(encrypted_payload, str) else encrypted_payload
        hmac_data = header_bytes + payload_bytes
        expected_hmac = hmac_mod.new(hmac_key, hmac_data, hashlib.sha256).hexdigest()

        if not hmac_mod.compare_digest(stored_hmac, expected_hmac):
            raise ValueError("HMAC完整性验证失败！数据可能被篡改。")

        # 解密
        if session_key and isinstance(encrypted_payload, str):
            mode = header.get("encrypt_mode", "GCM")
            if mode == "GCM":
                aad = json.dumps({"seq": header["sequence"], "src": header["src_ip"], "dst": header["dst_ip"]}).encode()
                payload = self.aes.decrypt_gcm(encrypted_payload, session_key, aad=aad)
            else:
                payload = self.aes.decrypt_cbc(encrypted_payload, session_key)
        else:
            payload = encrypted_payload

        # 解压
        if header.get("compressed"):
            payload = self._decompress(payload)

        # 统计
        self.stats.record_received(len(payload.encode('utf-8')))

        return payload

    def create_heartbeat_packet(self, session_key: bytes = None) -> dict:
        """创建心跳包"""
        hb = self.heartbeat.send_heartbeat()
        return self.encapsulate(
            payload=json.dumps(hb),
            src_ip="0.0.0.0",
            dst_ip="0.0.0.0",
            protocol="CUSTOM",
            session_key=session_key
        )

    def get_packet_info(self, packet: dict) -> str:
        header = packet.get("header", {})
        mode = header.get("encrypt_mode", "?")
        comp = "压缩" if header.get("compressed") else "未压缩"
        return (
            f"[Seq:{header.get('sequence', 'N/A')}] "
            f"{header.get('src_ip', '?')} -> {header.get('dst_ip', '?')} "
            f"Proto:{header.get('protocol', '?')} "
            f"Cipher:{mode} {comp} "
            f"Len:{header.get('payload_length', 'N/A')} "
            f"Flags:0x{header.get('flags', 0):02x}"
        )

    def get_stats(self) -> dict:
        return self.stats.get_stats()

    def get_heartbeat_status(self) -> dict:
        return self.heartbeat.get_status()

    def get_anti_replay_stats(self) -> dict:
        return self.anti_replay.get_stats()

    def create_handshake_request(self, client_id: str) -> dict:
        return {
            "type": "HANDSHAKE_REQUEST",
            "version": self.PROTOCOL_VERSION,
            "client_id": client_id,
            "timestamp": time.time(),
            "supported_protocols": ["TCP", "UDP"],
            "supported_ciphers": ["AES-256-GCM", "AES-256-CBC"],
            "supported_hashes": ["SHA-256", "SHA-384"],
            "compression": True
        }

    def create_handshake_response(self, server_id: str, session_id: str, dh_public_key: int) -> dict:
        return {
            "type": "HANDSHAKE_RESPONSE",
            "version": self.PROTOCOL_VERSION,
            "server_id": server_id,
            "session_id": session_id,
            "timestamp": time.time(),
            "dh_public_key": str(dh_public_key),
            "selected_protocol": "TCP",
            "selected_cipher": "AES-256-GCM",
            "selected_hash": "SHA-256",
            "compression": True
        }

    def create_session_confirm(self, session_id: str, dh_public_key: int) -> dict:
        return {
            "type": "SESSION_CONFIRM",
            "session_id": session_id,
            "dh_public_key": str(dh_public_key),
            "timestamp": time.time()
        }
