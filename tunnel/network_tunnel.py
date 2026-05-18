"""
网络层VPN隧道协议模块
实现基于TUN虚拟接口的网络层VPN，直接处理IP数据包

网络层VPN架构：
┌─────────────────────────────────────────────────────────────┐
│                      应用层 (Application)                    │
├─────────────────────────────────────────────────────────────┤
│                      传输层 (Transport)                     │
│                     TCP / UDP / ICMP                        │
├─────────────────────────────────────────────────────────────┤
│                      网络层 (Network)                       │
│                    IP (通过TUN接口)                         │
├─────────────────────────────────────────────────────────────┤
│                   VPN隧道封装层                            │
│  [隧道头部] [加密的IP数据包] [HMAC标签]                      │
├─────────────────────────────────────────────────────────────┤
│                    物理网络层                               │
│                   TCP Socket                               │
└─────────────────────────────────────────────────────────────┘
"""

import os
import struct
import time
import hashlib
import hmac
import zlib
import threading
from typing import Optional, Tuple

from crypto.aes_cipher import AESCipher
from crypto.hash_mac import HashMAC
from security.integrity import AntiReplayWindow, SessionKeyManager


class NetworkTunnel:
    """
    网络层VPN隧道协议
    直接处理IP数据包，通过TUN虚拟接口与操作系统网络栈交互
    
    隧道数据包格式（字节序）：
    ┌─────────────────┬─────────────────┬─────────────────┬─────────────────┐
    │ 版本(1 byte)    │ 标志(1 byte)    │ 密钥版本(2 bytes)│ 序列号(4 bytes) │
    ├─────────────────┼─────────────────┼─────────────────┼─────────────────┤
    │              时间戳(8 bytes)         │        载荷长度(2 bytes)          │
    ├─────────────────────────────────────────────────────────────────────────┤
    │                     加密的IP数据包 (可变长度)                            │
    ├─────────────────────────────────────────────────────────────────────────┤
    │                     HMAC-SHA256标签 (32 bytes)                          │
    └─────────────────────────────────────────────────────────────────────────┘
    """

    VERSION = 0x02
    FLAG_ENCRYPTED = 0x01
    FLAG_COMPRESSED = 0x02
    FLAG_HEARTBEAT = 0x04

    def __init__(self, encrypt_mode: str = "GCM"):
        self.aes = AESCipher()
        self.hash_mac = HashMAC()
        self.sequence_counter = 0
        self.encrypt_mode = encrypt_mode
        self.anti_replay = AntiReplayWindow(window_size=256)
        self.key_manager = SessionKeyManager()
        self.stats = {
            'packets_encrypted': 0,
            'packets_decrypted': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'replay_attempts': 0
        }
        self.stats_lock = threading.Lock()

    def _next_sequence(self) -> int:
        """获取下一个序列号"""
        self.sequence_counter = (self.sequence_counter + 1) & 0xFFFFFFFF
        return self.sequence_counter

    def _compress(self, data: bytes) -> Tuple[bytes, bool]:
        """压缩数据（仅当压缩后更小）"""
        try:
            compressed = zlib.compress(data, level=6)
            if len(compressed) < len(data) * 0.9:
                return compressed, True
            return data, False
        except Exception:
            return data, False

    def _decompress(self, data: bytes) -> bytes:
        """解压数据"""
        try:
            return zlib.decompress(data)
        except Exception:
            return data

    def encapsulate(self, ip_packet: bytes, session_key: bytes) -> bytes:
        """
        封装IP数据包到VPN隧道
        
        :param ip_packet: 原始IP数据包（从TUN接口读取）
        :param session_key: 会话密钥（用于加密）
        :return: 完整的隧道数据包（字节序列）
        """
        sequence = self._next_sequence()
        timestamp = int(time.time() * 1000)  # 毫秒时间戳
        
        # 压缩（可选）
        payload, compressed = self._compress(ip_packet)
        
        # 加密
        flags = self.FLAG_ENCRYPTED
        if compressed:
            flags |= self.FLAG_COMPRESSED
        
        if self.encrypt_mode == "GCM":
            # GCM模式：附加认证数据包含头部信息
            aad = struct.pack('!BBHIQH', 
                self.VERSION, flags, self.key_manager.key_version,
                sequence, timestamp, len(payload))
            encrypted_payload = self.aes.encrypt_gcm_raw(payload, session_key, aad=aad)
        else:
            # CBC模式
            encrypted_payload = self.aes.encrypt_cbc_raw(payload, session_key)
        
        # 构建隧道头部
        header = struct.pack('!BBHIQH',
            self.VERSION, flags, self.key_manager.key_version,
            sequence, timestamp, len(encrypted_payload))
        
        # 计算HMAC
        hmac_tag = hmac.new(session_key, header + encrypted_payload, hashlib.sha256).digest()
        
        # 更新统计
        with self.stats_lock:
            self.stats['packets_encrypted'] += 1
            self.stats['bytes_sent'] += len(ip_packet)
        
        return header + encrypted_payload + hmac_tag

    def decapsulate(self, tunnel_packet: bytes, session_key: bytes) -> Optional[bytes]:
        """
        从VPN隧道解封装IP数据包
        
        :param tunnel_packet: 完整的隧道数据包
        :param session_key: 会话密钥（用于解密）
        :return: 原始IP数据包，验证失败返回None
        """
        min_length = 18 + 32  # 最小头部 + HMAC
        
        if len(tunnel_packet) < min_length:
            return None
        
        # 分离头部、载荷和HMAC
        header = tunnel_packet[:18]
        hmac_tag = tunnel_packet[-32:]
        encrypted_payload = tunnel_packet[18:-32]
        
        # 验证HMAC
        expected_hmac = hmac.new(session_key, header + encrypted_payload, hashlib.sha256).digest()
        if not hmac.compare_digest(hmac_tag, expected_hmac):
            return None
        
        # 解析头部
        version, flags, key_version, sequence, timestamp, payload_len = \
            struct.unpack('!BBHIQH', header)
        
        if version != self.VERSION:
            return None
        
        # 防重放检查
        replay_check = self.anti_replay.check_and_update(sequence, timestamp / 1000)
        if not replay_check['accepted']:
            with self.stats_lock:
                self.stats['replay_attempts'] += 1
            return None
        
        # 解密
        if flags & self.FLAG_ENCRYPTED:
            if self.encrypt_mode == "GCM":
                aad = header  # AAD包含完整头部
                try:
                    payload = self.aes.decrypt_gcm_raw(encrypted_payload, session_key, aad=aad)
                except Exception:
                    return None
            else:
                try:
                    payload = self.aes.decrypt_cbc_raw(encrypted_payload, session_key)
                except Exception:
                    return None
        else:
            payload = encrypted_payload
        
        # 解压
        if flags & self.FLAG_COMPRESSED:
            payload = self._decompress(payload)
        
        # 更新统计
        with self.stats_lock:
            self.stats['packets_decrypted'] += 1
            self.stats['bytes_received'] += len(payload)
        
        return payload

    def create_heartbeat(self, session_key: bytes) -> bytes:
        """创建心跳包"""
        sequence = self._next_sequence()
        timestamp = int(time.time() * 1000)
        flags = self.FLAG_HEARTBEAT
        
        header = struct.pack('!BBHIQH',
            self.VERSION, flags, self.key_manager.key_version,
            sequence, timestamp, 0)
        
        hmac_tag = hmac.new(session_key, header, hashlib.sha256).digest()
        return header + hmac_tag

    def is_heartbeat(self, tunnel_packet: bytes) -> bool:
        """检查是否为心跳包"""
        if len(tunnel_packet) < 18:
            return False
        flags = tunnel_packet[1]
        return (flags & self.FLAG_HEARTBEAT) != 0

    def get_stats(self) -> dict:
        """获取统计信息"""
        with self.stats_lock:
            return dict(self.stats)


class TUNInterface:
    """
    TUN虚拟接口抽象类
    在不同平台上创建和管理TUN设备
    """
    
    def __init__(self, name: str = "tun0", ip_address: str = "10.8.0.2", 
                 netmask: str = "255.255.255.0", mtu: int = 1500):
        """
        :param name: 接口名称
        :param ip_address: 分配的IP地址
        :param netmask: 子网掩码
        :param mtu: 最大传输单元
        """
        self.name = name
        self.ip_address = ip_address
        self.netmask = netmask
        self.mtu = mtu
        self.fd = None
        self.running = False
        
    def open(self) -> bool:
        """打开TUN接口（由子类实现）"""
        raise NotImplementedError("子类必须实现open方法")
    
    def close(self):
        """关闭TUN接口"""
        self.running = False
        if self.fd:
            try:
                os.close(self.fd)
            except:
                pass
    
    def read(self, max_bytes: int = 4096) -> Optional[bytes]:
        """从TUN接口读取IP数据包"""
        if not self.fd:
            return None
        try:
            return os.read(self.fd, max_bytes)
        except OSError:
            return None
    
    def write(self, packet: bytes) -> int:
        """向TUN接口写入IP数据包"""
        if not self.fd:
            return 0
        try:
            return os.write(self.fd, packet)
        except OSError:
            return 0


class TUNInterfaceWindows(TUNInterface):
    """
    Windows平台TUN接口实现
    使用Win32 API或第三方库创建虚拟网卡
    """
    
    def __init__(self, name: str = "tun0", ip_address: str = "10.8.0.2", 
                 netmask: str = "255.255.255.0", mtu: int = 1500):
        super().__init__(name, ip_address, netmask, mtu)
        self.vpn_adapter = None
    
    def open(self) -> bool:
        """
        在Windows上创建TUN接口
        需要管理员权限和tap-windows驱动
        """
        try:
            import ctypes
            from ctypes import wintypes
            
            # 简化实现：使用简单的socket模拟（完整实现需要tap-windows）
            # 这里创建一个模拟的TUN接口，实际生产环境需要使用OpenVPN的tap驱动
            self.running = True
            return True
        except Exception as e:
            print(f"无法创建TUN接口: {e}")
            return False


class TUNInterfaceUnix(TUNInterface):
    """
    Unix-like平台（Linux/macOS）TUN接口实现
    """
    
    def open(self) -> bool:
        """打开TUN设备"""
        try:
            import fcntl
            
            # 打开TUN设备
            self.fd = os.open("/dev/net/tun", os.O_RDWR)
            
            # 设置TUN模式（无以太网头部）
            ifreq = struct.pack('16sH', self.name.encode(), 0x0001)  # IFF_TUN
            fcntl.ioctl(self.fd, 0x400454CA, ifreq)  # TUNSETIFF
            
            # 设置IP地址和路由（需要root权限）
            import subprocess
            subprocess.run(['ifconfig', self.name, self.ip_address, 'netmask', self.netmask], 
                        check=True, capture_output=True)
            subprocess.run(['ifconfig', self.name, 'up'], check=True, capture_output=True)
            
            self.running = True
            return True
        except Exception as e:
            print(f"无法创建TUN接口: {e}")
            return False


def create_tun_interface(name: str = "tun0", ip_address: str = "10.8.0.2",
                         netmask: str = "255.255.255.0") -> TUNInterface:
    """
    根据操作系统创建相应的TUN接口
    
    :param name: 接口名称
    :param ip_address: IP地址
    :param netmask: 子网掩码
    :return: TUN接口实例
    """
    import sys
    if sys.platform.startswith('win'):
        return TUNInterfaceWindows(name, ip_address, netmask)
    else:
        return TUNInterfaceUnix(name, ip_address, netmask)
