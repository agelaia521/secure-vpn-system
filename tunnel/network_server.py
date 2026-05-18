"""
网络层VPN服务端模块
基于TUN虚拟接口实现网络层VPN服务端
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


class NetworkLayerServer:
    """
    网络层VPN服务端
    功能:
    - 创建TUN虚拟接口
    - 监听客户端连接
    - 证书验证与身份认证
    - DH密钥交换
    - 网络层数据包转发（通过TUN接口）
    
    网络层架构:
    ┌──────────────────────────────────────────────────────┐
    │              内部网络 (10.8.0.0/24)                  │
    ├───────────────────┬─────────────────────────────────┤
    │     TUN接口       │                                 │
    │   (10.8.0.1)      │       VPN Server               │
    ├───────────────────┼─────────────────────────────────┤
    │     NetworkTunnel │     加密/解密/完整性验证          │
    ├───────────────────┼─────────────────────────────────┤
    │       TCP Socket  │                                 │
    └───────────────────┴─────────────────────────────────┘
                              │
                              ▼
                         外部网络
    """

    def __init__(self, config, logger: Logger = None):
        """
        初始化网络层VPN服务端
        :param config: VPN配置对象
        :param logger: 日志记录器
        """
        self.config = config
        self.logger = logger
        self.host = config.server_host
        self.port = config.server_port
        
        # VPN子网配置
        self.vpn_network = "10.8.0.0"
        self.vpn_netmask = "255.255.255.0"
        self.server_vpn_ip = "10.8.0.1"
        self.client_ip_pool = iter(range(2, 254))  # 客户端IP池
        
        # 密码学组件
        self.aes = AESCipher()
        self.rsa = RSACipher()
        self.dh = DHKeyExchange()
        self.digital_sig = DigitalSignature()
        self.tunnel = NetworkTunnel(encrypt_mode="GCM")
        
        # CA和证书
        self.ca = CertificateAuthority("SecureVPN-Network-CA", "CN")
        self.server_cert = self.ca.issue_certificate(
            subject="Network-VPN-Server",
            subject_info={"ip": self.host, "port": str(self.port), "vpn_ip": self.server_vpn_ip}
        )
        self.server_keypair = self.rsa.generate_key_pair()
        
        # TUN接口
        self.tun = None
        
        # 会话管理
        self.active_sessions = {}
        self.session_lock = threading.Lock()
        
        # 服务器状态
        self.running = False
        self.server_socket = None

    def start(self):
        """启动网络层VPN服务端"""
        # 初始化TUN接口
        self.tun = create_tun_interface("tun0", self.server_vpn_ip, self.vpn_netmask)
        if not self.tun.open():
            self.logger.error("无法创建TUN接口，服务启动失败")
            return
        
        self.logger.info(f"TUN接口已创建: {self.tun.name} ({self.server_vpn_ip})")
        
        # 启动服务器socket
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        self.logger.info(f"网络层VPN服务端已启动，监听 {self.host}:{self.port}")
        self.logger.info(f"VPN子网: {self.vpn_network}/{self.vpn_netmask}")
        self.logger.info(f"服务端VPN IP: {self.server_vpn_ip}")
        self.logger.info(f"服务端证书: {self.server_cert['serial_number']}")
        self.logger.info("等待客户端连接...")
        
        # 启动TUN接口读取线程
        tun_thread = threading.Thread(target=self._tun_read_loop, daemon=True)
        tun_thread.start()
        
        try:
            while self.running:
                try:
                    client_socket, client_addr = self.server_socket.accept()
                    self.logger.info(f"客户端连接: {client_addr}")
                    thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_addr),
                        daemon=True
                    )
                    thread.start()
                except OSError:
                    break
        except KeyboardInterrupt:
            self.logger.info("服务端正在关闭...")
        finally:
            self.stop()

    def stop(self):
        """停止VPN服务端"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        if self.tun:
            self.tun.close()
        self.logger.info("网络层VPN服务端已停止")

    def _tun_read_loop(self):
        """TUN接口读取循环 - 从TUN读取IP包并转发给客户端"""
        while self.running:
            try:
                # 从TUN接口读取IP数据包
                ip_packet = self.tun.read()
                if not ip_packet:
                    time.sleep(0.01)
                    continue
                
                # 解析目标IP
                dst_ip = self._parse_ip_dst(ip_packet)
                if not dst_ip:
                    continue
                
                # 查找目标客户端会话
                session = self._find_session_by_vpn_ip(dst_ip)
                if session:
                    # 加密并转发
                    encrypted_packet = self.tunnel.encapsulate(ip_packet, session['shared_key'])
                    self._send_raw(session['socket'], encrypted_packet)
                    self.logger.debug(f"转发IP包到 {dst_ip}: {len(ip_packet)} bytes")
            
            except Exception as e:
                self.logger.error(f"TUN读取循环异常: {e}")

    def _handle_client(self, client_socket: socket.socket, client_addr: tuple):
        """
        处理客户端连接
        :param client_socket: 客户端套接字
        :param client_addr: 客户端地址
        """
        session_id = str(uuid.uuid4())[:8]
        client_vpn_ip = f"10.8.0.{next(self.client_ip_pool, 254)}"
        
        self.logger.info(f"[会话 {session_id}] 开始处理客户端 {client_addr}")
        self.logger.info(f"[会话 {session_id}] 分配VPN IP: {client_vpn_ip}")
        
        try:
            # 步骤1: 接收握手请求
            self.logger.info(f"[会话 {session_id}] 等待握手请求...")
            request_data = self._recv_json(client_socket)
            if not request_data or request_data.get("type") != "HANDSHAKE_REQUEST":
                self.logger.error(f"[会话 {session_id}] 无效的握手请求")
                return
            
            client_id = request_data.get("client_id", "Unknown")
            self.logger.info(f"[会话 {session_id}] 客户端ID: {client_id}")
            
            # 步骤2: 发送证书和DH公钥
            dh_pub, dh_priv = self.dh.generate_key_pair()
            response = {
                "type": "HANDSHAKE_RESPONSE",
                "version": 2,
                "server_id": "Network-VPN-Server",
                "session_id": session_id,
                "vpn_ip": client_vpn_ip,
                "vpn_network": self.vpn_network,
                "vpn_netmask": self.vpn_netmask,
                "dh_public_key": str(dh_pub),
                "certificate": self.server_cert,
                "server_public_key": self.rsa.export_public_key_pem(self.server_keypair["public_key"])
            }
            self._send_json(client_socket, response)
            self.logger.info(f"[会话 {session_id}] 已发送握手响应、证书和VPN配置")
            
            # 步骤3: 接收客户端DH公钥和会话确认
            confirm_data = self._recv_json(client_socket)
            if not confirm_data or confirm_data.get("type") != "SESSION_CONFIRM":
                self.logger.error(f"[会话 {session_id}] 未收到会话确认")
                return
            
            client_dh_pub = int(confirm_data["dh_public_key"])
            client_cert = confirm_data.get("certificate")
            
            # 验证客户端证书
            if client_cert:
                cert_valid = self.ca.verify_certificate(client_cert)
                self.logger.info(
                    f"[会话 {session_id}] 客户端证书验证: "
                    f"{'通过 ✓' if cert_valid else '失败 ✗'}"
                )
                if not cert_valid:
                    self.logger.error(f"[会话 {session_id}] 客户端证书无效，拒绝连接")
                    return
            
            # 步骤4: 计算共享密钥
            shared_key = self.dh.compute_shared_secret(client_dh_pub)
            self.logger.info(
                f"[会话 {session_id}] DH密钥交换完成，"
                f"共享密钥: {shared_key.hex()[:16]}..."
            )
            
            # 保存会话
            with self.session_lock:
                self.active_sessions[session_id] = {
                    "client_id": client_id,
                    "client_addr": client_addr,
                    "vpn_ip": client_vpn_ip,
                    "shared_key": shared_key,
                    "dh_private_key": dh_priv,
                    "socket": client_socket,
                    "connected_at": time.time(),
                    "packet_count": 0
                }
            
            self.logger.info(f"[会话 {session_id}] 网络层VPN隧道已建立 ✓")
            self.logger.info(f"[会话 {session_id}] 客户端VPN IP: {client_vpn_ip}")
            
            # 步骤5: 数据转发循环
            self._data_loop(client_socket, session_id, shared_key)
            
        except Exception as e:
            self.logger.error(f"[会话 {session_id}] 处理异常: {e}")
        finally:
            client_socket.close()
            with self.session_lock:
                if session_id in self.active_sessions:
                    del self.active_sessions[session_id]
            self.logger.info(f"[会话 {session_id}] 连接已关闭")

    def _data_loop(self, client_socket: socket.socket, session_id: str, shared_key: bytes):
        """
        数据转发循环 - 接收客户端加密数据包并写入TUN接口
        """
        while self.running:
            try:
                # 接收原始隧道数据包
                packet = self._recv_raw(client_socket)
                if not packet:
                    break
                
                # 检查是否为心跳包
                if self.tunnel.is_heartbeat(packet):
                    continue  # 忽略心跳包
                
                # 解封装IP数据包
                ip_packet = self.tunnel.decapsulate(packet, shared_key)
                if ip_packet:
                    # 写入TUN接口
                    self.tun.write(ip_packet)
                    
                    with self.session_lock:
                        if session_id in self.active_sessions:
                            self.active_sessions[session_id]["packet_count"] += 1
                    
                    # 解析源IP用于日志
                    src_ip = self._parse_ip_src(ip_packet)
                    dst_ip = self._parse_ip_dst(ip_packet)
                    self.logger.debug(
                        f"[会话 {session_id}] 收到IP包: {src_ip} -> {dst_ip}, "
                        f"长度: {len(ip_packet)} bytes"
                    )
                else:
                    self.logger.warning(f"[会话 {session_id}] 数据包验证失败")
            
            except Exception as e:
                self.logger.error(f"[会话 {session_id}] 数据接收异常: {e}")
                break

    def _find_session_by_vpn_ip(self, vpn_ip: str):
        """根据VPN IP查找会话"""
        with self.session_lock:
            for session in self.active_sessions.values():
                if session["vpn_ip"] == vpn_ip:
                    return session
        return None

    @staticmethod
    def _parse_ip_src(ip_packet: bytes) -> Optional[str]:
        """从IP数据包解析源IP"""
        if len(ip_packet) < 20:
            return None
        # IPv4头部格式：版本(4位)+IHL(4位), TOS(1), 总长度(2), 标识(2), 
        # 标志(3位)+分段偏移(13位), TTL(1), 协议(1), 校验和(2), 源IP(4), 目的IP(4)
        src_bytes = ip_packet[12:16]
        return ".".join(str(b) for b in src_bytes)

    @staticmethod
    def _parse_ip_dst(ip_packet: bytes) -> Optional[str]:
        """从IP数据包解析目的IP"""
        if len(ip_packet) < 20:
            return None
        dst_bytes = ip_packet[16:20]
        return ".".join(str(b) for b in dst_bytes)

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
        if length > 65535:  # 安全限制
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

    def get_status(self) -> dict:
        """获取服务端状态"""
        with self.session_lock:
            return {
                "running": self.running,
                "listen_address": f"{self.host}:{self.port}",
                "vpn_network": f"{self.vpn_network}/{self.vpn_netmask}",
                "server_vpn_ip": self.server_vpn_ip,
                "active_sessions": len(self.active_sessions),
                "sessions": [
                    {"id": sid, "vpn_ip": s["vpn_ip"], "client_addr": s["client_addr"]}
                    for sid, s in self.active_sessions.items()
                ],
                "certificate": self.server_cert["serial_number"]
            }
