"""
VPN 客户端模块
实现VPN客户端的连接、认证、隧道建立和安全通信
"""

import os
import uuid
import json
import socket
import time
from typing import Optional

from crypto.aes_cipher import AESCipher
from crypto.rsa_cipher import RSACipher
from security.digital_signature import DigitalSignature
from security.certificate import CertificateAuthority
from security.key_exchange import DHKeyExchange
from tunnel.tunnel_protocol import TunnelProtocol
from utils.logger import Logger


class VPNClient:
    """
    VPN客户端
    功能:
    - 连接VPN服务端
    - 验证服务端证书
    - DH密钥交换
    - 安全隧道通信
    - 数据加密发送
    """

    def __init__(self, config, logger: Logger = None):
        """
        初始化VPN客户端
        :param config: VPN配置对象
        :param logger: 日志记录器
        """
        self.config = config
        self.logger = logger
        self.server_host = config.server_host
        self.server_port = config.server_port

        # 密码学组件
        self.aes = AESCipher()
        self.rsa = RSACipher()
        self.dh = DHKeyExchange()
        self.digital_sig = DigitalSignature()
        self.tunnel = TunnelProtocol()

        # CA和客户端证书
        self.ca = CertificateAuthority("SecureVPN-CA", "CN")
        self.client_cert = self.ca.issue_certificate(
            subject="VPN-Client",
            subject_info={"organization": "SecureVPN", "country": "CN"}
        )
        self.client_keypair = self.rsa.generate_key_pair()

        # 会话信息
        self.session_id = None
        self.shared_key = None
        self.connected = False
        self.socket = None

    def connect(self):
        """
        连接VPN服务端并建立安全隧道
        """
        self.logger.info(f"正在连接 {self.server_host}:{self.server_port}...")

        try:
            # 建立TCP连接
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((self.server_host, self.server_port))
            self.logger.info("TCP连接已建立")

            # 步骤1: 发送握手请求
            self.client_id = str(uuid.uuid4())[:8]
            handshake = self.tunnel.create_handshake_request(
                client_id=f"Client-{self.client_id}"
            )
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
            self.session_id = response.get("session_id", self.client_id)

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

            # 步骤3: 发送客户端DH公钥和证书
            dh_pub, dh_priv = self.dh.generate_key_pair()
            confirm = self.tunnel.create_session_confirm(
                session_id=self.session_id,
                dh_public_key=dh_pub
            )
            confirm["certificate"] = self.client_cert
            confirm["client_public_key"] = self.rsa.export_public_key_pem(
                self.client_keypair["public_key"]
            )
            self._send_json(self.socket, confirm)
            self.logger.info("会话确认和DH公钥已发送")

            # 步骤4: 计算共享密钥
            self.shared_key = self.dh.compute_shared_secret(server_dh_pub)
            self.logger.info(
                f"DH密钥交换完成，共享密钥: {self.shared_key.hex()[:16]}..."
            )

            self.connected = True
            self.logger.info(f"安全隧道已建立 ✓ (会话: {self.session_id})")
            self.logger.info(f"当前客户端ID: Client-{self.client_id}")
            self.logger.info(f"共享密钥: {self.shared_key.hex()[:16]}...")

            # 步骤5: 进入交互模式
            self._interactive_mode()

        except ConnectionRefusedError:
            self.logger.error(f"连接被拒绝，请确认服务端正在运行")
        except socket.timeout:
            self.logger.error("连接超时")
        except Exception as e:
            self.logger.error(f"连接异常: {e}")
        finally:
            self.disconnect()

    def send_data(self, message: str) -> bool:
        """
        通过安全隧道发送数据
        :param message: 待发送的消息
        :return: 发送是否成功
        """
        if not self.connected or not self.shared_key:
            self.logger.error("未建立安全隧道，无法发送数据")
            return False

        try:
            # 封装数据包
            packet = self.tunnel.encapsulate(
                payload=message,
                src_ip="10.0.0.2",
                dst_ip="10.0.0.1",
                protocol="TCP",
                session_key=self.shared_key
            )

            data = {
                "type": "DATA",
                "packet": packet
            }

            self._send_json(self.socket, data)
            self.logger.info(f"数据已发送: {self.tunnel.get_packet_info(packet)}")

            # 等待ACK
            ack = self._recv_json(self.socket)
            if ack and ack.get("type") == "ACK":
                self.logger.info(f"服务端确认: 序列号={ack.get('sequence')}")
                return True

            return False

        except Exception as e:
            self.logger.error(f"数据发送失败: {e}")
            return False

    def _interactive_mode(self):
        """交互式通信模式"""
        self.logger.info("\n" + "=" * 50)
        self.logger.info("  安全隧道已就绪")
        self.logger.info("  发送消息格式: 目标ID|消息内容")
        self.logger.info("  示例: Client-Bob|Hello from Alice")
        self.logger.info("  输入 'quit' 断开连接")
        self.logger.info("  输入 'list' 查看在线客户端")
        self.logger.info("=" * 50 + "\n")

        # 启动接收线程
        import threading
        recv_thread = threading.Thread(target=self._receive_loop, daemon=True)
        recv_thread.start()

        while self.connected:
            try:
                message = input("VPN> ")
                if message.lower() in ('quit', 'exit', 'q'):
                    break
                if message.lower() == 'list':
                    self.logger.info("命令功能: 显示在线客户端")
                    continue
                if message.strip():
                    self.send_data(message)
            except EOFError:
                break
            except KeyboardInterrupt:
                break

    def _receive_loop(self):
        """接收服务端消息循环"""
        while self.connected:
            try:
                self.socket.settimeout(1.0)
                data = self._recv_json(self.socket)
                if not data:
                    continue
                
                if data.get("type") == "FORWARD":
                    # 收到转发消息
                    packet = data["packet"]
                    payload = self.tunnel.decapsulate(packet, self.shared_key)
                    
                    # 解析格式: FROM:源ID|消息内容
                    if payload.startswith("FROM:"):
                        from_part = payload[5:]
                        if "|" in from_part:
                            source_id, message = from_part.split("|", 1)
                            print(f"\n[收到消息] {source_id}: {message}")
                            print("VPN> ", end="", flush=True)
                        else:
                            print(f"\n[收到消息] {from_part}")
                            print("VPN> ", end="", flush=True)
                            
                elif data.get("type") == "ACK":
                    # ACK确认
                    pass
                    
            except socket.timeout:
                continue
            except Exception as e:
                if self.connected:
                    self.logger.error(f"接收消息异常: {e}")
                break

    def disconnect(self):
        """断开VPN连接"""
        if self.connected and self.socket:
            try:
                disconnect_msg = {"type": "DISCONNECT"}
                self._send_json(self.socket, disconnect_msg)
            except Exception:
                pass

        self.connected = False
        if self.socket:
            self.socket.close()
            self.socket = None
        self.logger.info("VPN连接已断开")

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
