"""
网络层VPN客户端模块
基于TUN虚拟接口实现网络层VPN客户端
"""

import os
import sys
import uuid
import json
import socket
import threading
import time
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.aes_cipher import AESCipher
from crypto.rsa_cipher import RSACipher
from security.digital_signature import DigitalSignature
from security.certificate import CertificateAuthority
from security.key_exchange import DHKeyExchange
from tunnel.network_tunnel import NetworkTunnel, create_tun_interface
from utils.logger import Logger


class NetworkLayerClient:
    """
    网络层VPN客户端
    功能:
    - 创建TUN虚拟接口
    - 连接VPN服务端
    - 验证服务端证书
    - DH密钥交换
    - 网络层数据包转发（通过TUN接口）
    
    网络层架构:
    ┌──────────────────────────────────────────────────────┐
    │              应用程序 (浏览器/SSH等)                 │
    ├──────────────────────────────────────────────────────┤
    │              操作系统网络栈                          │
    ├───────────────────┬─────────────────────────────────┤
    │     TUN接口       │                                 │
    │   (10.8.0.x)      │       VPN Client               │
    ├───────────────────┼─────────────────────────────────┤
    │     NetworkTunnel │     加密/解密/完整性验证          │
    ├───────────────────┼─────────────────────────────────┤
    │       TCP Socket  │                                 │
    └───────────────────┴─────────────────────────────────┘
                              │
                              ▼
                         外部网络 → VPN Server
    """

    def __init__(self, config, logger: Logger = None):
        """
        初始化网络层VPN客户端
        :param config: VPN配置对象
        :param logger: 日志记录器
        """
        self.config = config
        self.logger = logger
        self.server_host = config.server_host
        self.server_port = config.server_port
        
        # VPN配置（由服务端分配）
        self.vpn_ip = None
        self.vpn_network = None
        self.vpn_netmask = None
        
        # 密码学组件
        self.aes = AESCipher()
        self.rsa = RSACipher()
        self.dh = DHKeyExchange()
        self.digital_sig = DigitalSignature()
        self.tunnel = NetworkTunnel(encrypt_mode="GCM")
        
        # CA和客户端证书
        self.ca = CertificateAuthority("SecureVPN-Network-CA", "CN")
        self.client_cert = self.ca.issue_certificate(
            subject="Network-VPN-Client",
            subject_info={"organization": "SecureVPN", "country": "CN"}
        )
        self.client_keypair = self.rsa.generate_key_pair()
        
        # TUN接口
        self.tun = None
        
        # 会话信息
        self.session_id = None
        self.shared_key = None
        self.connected = False
        self.socket = None

    def connect(self):
        """
        连接网络层VPN服务端并建立安全隧道
        """
        self.logger.info(f"正在连接网络层VPN服务端 {self.server_host}:{self.server_port}...")
        
        try:
            # 建立TCP连接
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((self.server_host, self.server_port))
            self.logger.info("TCP连接已建立")
            
            # 步骤1: 发送握手请求
            self.session_id = str(uuid.uuid4())[:8]
            handshake = {
                "type": "HANDSHAKE_REQUEST",
                "version": 2,
                "client_id": f"Network-Client-{self.session_id}",
                "timestamp": time.time(),
                "supported_ciphers": ["AES-256-GCM", "AES-256-CBC"]
            }
            self._send_json(self.socket, handshake)
            self.logger.info("握手请求已发送")
            
            # 步骤2: 接收服务端响应和证书
            response = self._recv_json(self.socket)
            if not response or response.get("type") != "HANDSHAKE_RESPONSE":
                self.logger.error("无效的服务端响应")
                return
            
            server_cert = response.get("certificate")
            server_pub_key_pem = response.get("server_public_key")
            server_dh_pub = int(response["dh_public_key"])
            self.session_id = response.get("session_id", self.session_id)
            
            # 获取VPN配置
            self.vpn_ip = response.get("vpn_ip")
            self.vpn_network = response.get("vpn_network")
            self.vpn_netmask = response.get("vpn_netmask")
            
            # 验证服务端证书
            if server_cert:
                cert_valid = self.ca.verify_certificate(server_cert)
                self.logger.info(
                    f"服务端证书验证: {'通过 ✓' if cert_valid else '失败 ✗'}"
                )
                self.logger.info(
                    f"  证书主题: {server_cert.get('subject', 'N/A')}"
                )
                self.logger.info(
                    f"  证书序列号: {server_cert.get('serial_number', 'N/A')}"
                )
                
                if not cert_valid:
                    self.logger.error("服务端证书无效，中止连接")
                    self.disconnect()
                    return
            
            # 步骤3: 创建TUN接口
            self.tun = create_tun_interface("tun0", self.vpn_ip, self.vpn_netmask)
            if not self.tun.open():
                self.logger.error("无法创建TUN接口")
                self.disconnect()
                return
            self.logger.info(f"TUN接口已创建: {self.tun.name} ({self.vpn_ip})")
            
            # 步骤4: 发送客户端DH公钥和证书
            dh_pub, dh_priv = self.dh.generate_key_pair()
            confirm = {
                "type": "SESSION_CONFIRM",
                "session_id": self.session_id,
                "dh_public_key": str(dh_pub),
                "certificate": self.client_cert,
                "client_public_key": self.rsa.export_public_key_pem(self.client_keypair["public_key"])
            }
            self._send_json(self.socket, confirm)
            self.logger.info("会话确认和DH公钥已发送")
            
            # 步骤5: 计算共享密钥
            self.shared_key = self.dh.compute_shared_secret(server_dh_pub)
            self.logger.info(
                f"DH密钥交换完成，共享密钥: {self.shared_key.hex()[:16]}..."
            )
            
            self.connected = True
            self.logger.info(f"网络层VPN隧道已建立 ✓ (会话: {self.session_id})")
            self.logger.info(f"VPN IP: {self.vpn_ip}")
            self.logger.info(f"VPN网络: {self.vpn_network}/{self.vpn_netmask}")
            self.logger.info(f"服务端VPN IP: 10.8.0.1")
            
            # 启动TUN读取线程
            tun_thread = threading.Thread(target=self._tun_read_loop, daemon=True)
            tun_thread.start()
            
            # 步骤6: 进入数据转发循环
            self._data_loop()
            
        except ConnectionRefusedError:
            self.logger.error(f"连接被拒绝，请确认服务端正在运行")
        except socket.timeout:
            self.logger.error("连接超时")
        except Exception as e:
            self.logger.error(f"连接异常: {e}")
        finally:
            self.disconnect()

    def _tun_read_loop(self):
        """TUN接口读取循环 - 从TUN读取IP包并加密发送"""
        while self.connected:
            try:
                # 从TUN接口读取IP数据包
                ip_packet = self.tun.read()
                if not ip_packet:
                    time.sleep(0.01)
                    continue
                
                # 加密并发送
                if self.shared_key:
                    encrypted_packet = self.tunnel.encapsulate(ip_packet, self.shared_key)
                    self._send_raw(self.socket, encrypted_packet)
                    # 解析源IP用于日志
                    src_ip = self._parse_ip_src(ip_packet)
                    dst_ip = self._parse_ip_dst(ip_packet)
                    self.logger.debug(
                        f"发送IP包: {src_ip} -> {dst_ip}, 长度: {len(ip_packet)} bytes"
                    )
            
            except Exception as e:
                self.logger.error(f"TUN读取循环异常: {e}")
                break

    def _data_loop(self):
        """
        数据接收循环 - 接收服务端加密数据包并写入TUN接口
        """
        self.socket.settimeout(None)
        while self.connected:
            try:
                # 接收原始隧道数据包
                packet = self._recv_raw(self.socket)
                if not packet:
                    break
                
                # 检查是否为心跳包
                if self.tunnel.is_heartbeat(packet):
                    continue  # 忽略心跳包
                
                # 解封装IP数据包
                ip_packet = self.tunnel.decapsulate(packet, self.shared_key)
                if ip_packet:
                    # 写入TUN接口
                    self.tun.write(ip_packet)
                    
                    # 解析源IP用于日志
                    src_ip = self._parse_ip_src(ip_packet)
                    dst_ip = self._parse_ip_dst(ip_packet)
                    self.logger.debug(
                        f"收到IP包: {src_ip} -> {dst_ip}, 长度: {len(ip_packet)} bytes"
                    )
                else:
                    self.logger.warning("数据包验证失败")
            
            except Exception as e:
                self.logger.error(f"数据接收异常: {e}")
                break

    @staticmethod
    def _parse_ip_src(ip_packet: bytes) -> Optional[str]:
        """从IP数据包解析源IP"""
        if len(ip_packet) < 20:
            return None
        src_bytes = ip_packet[12:16]
        return ".".join(str(b) for b in src_bytes)

    @staticmethod
    def _parse_ip_dst(ip_packet: bytes) -> Optional[str]:
        """从IP数据包解析目的IP"""
        if len(ip_packet) < 20:
            return None
        dst_bytes = ip_packet[16:20]
        return ".".join(str(b) for b in dst_bytes)

    def disconnect(self):
        """断开VPN连接"""
        self.connected = False
        
        if self.tun:
            self.tun.close()
        
        if self.socket:
            try:
                disconnect_msg = {"type": "DISCONNECT"}
                self._send_json(self.socket, disconnect_msg)
            except Exception:
                pass
            self.socket.close()
            self.socket = None
        
        self.logger.info("网络层VPN连接已断开")

    def _send_json(self, sock: socket.socket, data: dict):
        """发送JSON数据"""
        msg = json.dumps(data).encode('utf-8')
        length = len(msg)
        sock.sendall(length.to_bytes(4, 'big') + msg)

    def _recv_json(self, sock: socket.socket) -> Optional[dict]:
        """接收JSON数据"""
        length_data = self._recv_exact(sock, 4)
        if not length_data:
            return None
        length = int.from_bytes(length_data, 'big')
        msg_data = self._recv_exact(sock, length)
        if not msg_data:
            return None
        return json.loads(msg_data.decode('utf-8'))

    def _send_raw(self, sock: socket.socket, data: bytes):
        """发送原始二进制数据"""
        length = len(data)
        sock.sendall(length.to_bytes(4, 'big') + data)

    def _recv_raw(self, sock: socket.socket) -> Optional[bytes]:
        """接收原始二进制数据"""
        length_data = self._recv_exact(sock, 4)
        if not length_data:
            return None
        length = int.from_bytes(length_data, 'big')
        if length > 65535:
            return None
        return self._recv_exact(sock, length)

    def _recv_exact(self, sock: socket.socket, n: int) -> Optional[bytes]:
        """精确接收n字节"""
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data
