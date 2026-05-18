"""
VPN 服务端模块
实现VPN服务端的连接管理、认证、隧道建立和数据转发
"""

import os
import uuid
import json
import socket
import threading
import time
from typing import Optional, Callable

from crypto.aes_cipher import AESCipher
from crypto.rsa_cipher import RSACipher
from security.digital_signature import DigitalSignature
from security.certificate import CertificateAuthority
from security.key_exchange import DHKeyExchange
from tunnel.tunnel_protocol import TunnelProtocol
from utils.logger import Logger


class VPNServer:
    """
    VPN服务端
    功能:
    - 监听客户端连接
    - 证书验证与身份认证
    - DH密钥交换
    - 安全隧道建立
    - 数据加密转发
    """

    def __init__(self, config, logger: Logger = None):
        """
        初始化VPN服务端
        :param config: VPN配置对象
        :param logger: 日志记录器
        """
        self.config = config
        self.logger = logger
        self.host = config.server_host
        self.port = config.server_port

        # 密码学组件
        self.aes = AESCipher()
        self.rsa = RSACipher()
        self.dh = DHKeyExchange()
        self.digital_sig = DigitalSignature()
        self.tunnel = TunnelProtocol()

        # CA和证书
        self.ca = CertificateAuthority("SecureVPN-CA", "CN")
        self.server_cert = self.ca.issue_certificate(
            subject="VPN-Server",
            subject_info={"ip": self.host, "port": str(self.port)}
        )
        self.server_keypair = self.rsa.generate_key_pair()

        # 会话管理
        self.active_sessions = {}
        self.session_lock = threading.Lock()

        # 服务器状态
        self.running = False
        self.server_socket = None

    def start(self):
        """启动VPN服务端"""
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)

        self.logger.info(f"VPN服务端已启动，监听 {self.host}:{self.port}")
        self.logger.info(f"服务端证书: {self.server_cert['serial_number']}")
        self.logger.info(f"等待客户端连接...")

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
        self.logger.info("VPN服务端已停止")

    def _handle_client(self, client_socket: socket.socket, client_addr: tuple):
        """
        处理客户端连接
        :param client_socket: 客户端套接字
        :param client_addr: 客户端地址
        """
        session_id = str(uuid.uuid4())[:8]
        self.logger.info(f"[会话 {session_id}] 开始处理客户端 {client_addr}")

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
            response = self.tunnel.create_handshake_response(
                server_id="VPN-Server",
                session_id=session_id,
                dh_public_key=dh_pub
            )
            response["certificate"] = self.server_cert
            response["server_public_key"] = self.rsa.export_public_key_pem(
                self.server_keypair["public_key"]
            )
            self._send_json(client_socket, response)
            self.logger.info(f"[会话 {session_id}] 已发送握手响应和证书")

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

            # 保存会话（包含socket引用用于转发）
            with self.session_lock:
                self.active_sessions[session_id] = {
                    "client_id": client_id,
                    "client_addr": client_addr,
                    "client_socket": client_socket,
                    "shared_key": shared_key,
                    "dh_private_key": dh_priv,
                    "connected_at": time.time(),
                    "packet_count": 0
                }

            self.logger.info(f"[会话 {session_id}] 安全隧道已建立 ✓")

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
        数据转发循环
        :param client_socket: 客户端套接字
        :param session_id: 会话ID
        :param shared_key: 共享密钥
        """
        while self.running:
            try:
                data = self._recv_json(client_socket)
                if not data:
                    break

                if data.get("type") == "DATA":
                    try:
                        packet = data["packet"]
                        payload = self.tunnel.decapsulate(packet, shared_key)
                        with self.session_lock:
                            if session_id in self.active_sessions:
                                self.active_sessions[session_id]["packet_count"] += 1

                        self.logger.info(
                            f"[会话 {session_id}] 收到数据: "
                            f"{self.tunnel.get_packet_info(packet)}"
                        )

                        # 解析消息格式: "目标ID|消息内容"
                        if "|" in payload:
                            target_id, message = payload.split("|", 1)
                            target_id = target_id.strip()
                            message = message.strip()
                            
                            self.logger.info(f"[会话 {session_id}] 转发消息到 {target_id}: {message[:50]}...")
                            
                            # 查找目标客户端（支持session_id和client_id两种格式）
                            target_session = None
                            with self.session_lock:
                                for sid, info in self.active_sessions.items():
                                    # 支持: session_id、Client-session_id、原始client_id
                                    client_id = info["client_id"]
                                    if (sid == target_id or 
                                        client_id == target_id or 
                                        f"Client-{sid}" == target_id):
                                        target_session = sid
                                        break
                            
                            if target_session and target_session != session_id:
                                # 转发消息
                                self._forward_message(target_session, session_id, message)
                                self.logger.info(f"[会话 {session_id}] 消息已转发")
                            elif target_session == session_id:
                                self.logger.warning(f"[会话 {session_id}] 不能发送消息给自己")
                            else:
                                self.logger.warning(f"[会话 {session_id}] 目标客户端 {target_id} 不存在")
                            
                            ack_status = "FORWARDED" if target_session else "TARGET_NOT_FOUND"
                        else:
                            self.logger.info(f"[会话 {session_id}] 解密内容: {payload[:50]}...")
                            ack_status = "RECEIVED"

                        ack = {
                            "type": "ACK",
                            "sequence": packet["header"]["sequence"],
                            "status": ack_status
                        }
                        self._send_json(client_socket, ack)

                    except ValueError as e:
                        self.logger.error(f"[会话 {session_id}] 数据解密失败: {e}")

                elif data.get("type") == "DISCONNECT":
                    self.logger.info(f"[会话 {session_id}] 客户端请求断开")
                    break

            except Exception as e:
                self.logger.error(f"[会话 {session_id}] 数据接收异常: {e}")
                break

    def _forward_message(self, target_session_id: str, source_session_id: str, message: str):
        """
        转发消息到目标客户端
        :param target_session_id: 目标会话ID
        :param source_session_id: 源会话ID
        :param message: 消息内容
        """
        with self.session_lock:
            if target_session_id not in self.active_sessions:
                return
            
            target_info = self.active_sessions[target_session_id]
            source_info = self.active_sessions.get(source_session_id, {})
            
            # 重新封装消息，添加源信息
            forwarded_payload = f"FROM:{source_info.get('client_id', source_session_id)}|{message}"
            
            # 使用目标会话的密钥重新加密
            packet = self.tunnel.encapsulate(
                payload=forwarded_payload,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.3",
                protocol="TCP",
                session_key=target_info["shared_key"]
            )
            
            # 发送转发消息
            try:
                forward_data = {
                    "type": "FORWARD",
                    "packet": packet
                }
                self._send_json(target_info["client_socket"], forward_data)
                self.logger.info(f"[会话 {target_session_id}] 转发消息已发送")
            except Exception as e:
                self.logger.error(f"[会话 {target_session_id}] 转发消息失败: {e}")

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
                "active_sessions": len(self.active_sessions),
                "sessions": list(self.active_sessions.keys()),
                "certificate": self.server_cert["serial_number"]
            }
