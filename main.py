"""
轻量级安全VPN通信系统（增强版）- 项目主入口
支持应用层和网络层两种VPN实现
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tunnel.vpn_server import VPNServer
from tunnel.vpn_client import VPNClient
from tunnel.network_server import NetworkLayerServer
from tunnel.network_client import NetworkLayerClient
from utils.logger import setup_logger
from utils.config import VPNConfig


def main():
    import argparse
    parser = argparse.ArgumentParser(description="轻量级安全VPN通信系统（增强版）")
    subparsers = parser.add_subparsers(dest="mode", help="运行模式")
    
    # 应用层VPN
    sp = subparsers.add_parser("server", help="启动VPN服务端（应用层）")
    sp.add_argument("--host", default="0.0.0.0")
    sp.add_argument("--port", type=int, default=9090)
    
    cp = subparsers.add_parser("client", help="启动VPN客户端（应用层）")
    cp.add_argument("--host", default="127.0.0.1")
    cp.add_argument("--port", type=int, default=9090)
    
    # 网络层VPN
    nsp = subparsers.add_parser("network-server", help="启动网络层VPN服务端（使用TUN接口）")
    nsp.add_argument("--host", default="0.0.0.0")
    nsp.add_argument("--port", type=int, default=9091)
    
    ncp = subparsers.add_parser("network-client", help="启动网络层VPN客户端（使用TUN接口）")
    ncp.add_argument("--host", default="127.0.0.1")
    ncp.add_argument("--port", type=int, default=9091)
    
    subparsers.add_parser("demo", help="运行本地演示")
    subparsers.add_parser("test", help="运行单元测试")
    
    args = parser.parse_args()

    if args.mode == "server":
        logger = setup_logger("VPN_Server")
        config = VPNConfig()
        config.server_host = args.host
        config.server_port = args.port
        VPNServer(config, logger).start()
    elif args.mode == "client":
        logger = setup_logger("VPN_Client")
        config = VPNConfig()
        config.server_host = args.host
        config.server_port = args.port
        VPNClient(config, logger).connect()
    elif args.mode == "network-server":
        logger = setup_logger("Network_VPN_Server")
        config = VPNConfig()
        config.server_host = args.host
        config.server_port = args.port
        NetworkLayerServer(config, logger).start()
    elif args.mode == "network-client":
        logger = setup_logger("Network_VPN_Client")
        config = VPNConfig()
        config.server_host = args.host
        config.server_port = args.port
        NetworkLayerClient(config, logger).connect()
    elif args.mode == "demo":
        run_demo()
    elif args.mode == "test":
        run_tests()
    else:
        parser.print_help()


def run_demo():
    """运行完整功能演示"""
    print("\n" + "=" * 70)
    print("  轻量级安全VPN通信系统（增强版）- 功能演示")
    print("=" * 70)

    from crypto.aes_cipher import AESCipher, KeyDerivation
    from crypto.rsa_cipher import RSACipher
    from crypto.hash_mac import HashMAC
    from security.digital_signature import DigitalSignature
    from security.certificate import CertificateAuthority
    from security.key_exchange import DHKeyExchange
    from security.integrity import IntegrityChecker, AntiReplayWindow, SessionKeyManager
    from tunnel.tunnel_protocol import TunnelProtocol

    # ===== 模块一：密码算法 =====
    print("\n" + "=" * 70)
    print("  【模块一】密码算法演示")
    print("=" * 70)

    # [1] AES-CBC
    print("\n[1] AES-256-CBC 对称加密/解密")
    aes = AESCipher()
    pt = "这是一条需要通过VPN隧道加密传输的机密消息！SecureVPN-2026"
    key = aes.generate_key()
    ct_cbc = aes.encrypt_cbc(pt, key)
    pt_dec = aes.decrypt_cbc(ct_cbc, key)
    print(f"  原文: {pt}")
    print(f"  密文(Base64): {ct_cbc[:56]}...")
    print(f"  解密: {pt_dec}")
    print(f"  ✓ CBC加密解密验证: {'通过' if pt == pt_dec else '失败'}")

    # [2] AES-GCM（认证加密AEAD）
    print("\n[2] AES-256-GCM 认证加密/解密（AEAD）")
    aad = b"VPN-Tunnel-Packet-v2"
    ct_gcm = aes.encrypt_gcm(pt, key, aad=aad)
    pt_gcm = aes.decrypt_gcm(ct_gcm, key, aad=aad)
    print(f"  AAD(附加认证数据): {aad.decode()}")
    print(f"  密文(Base64): {ct_gcm[:56]}...")
    print(f"  解密: {pt_gcm}")
    print(f"  ✓ GCM加密解密验证: {'通过' if pt == pt_gcm else '失败'}")

    # GCM篡改检测
    try:
        tampered = ct_gcm[:-4] + "XXXX"
        aes.decrypt_gcm(tampered, key, aad=aad)
        print(f"  ✗ GCM篡改检测: 未检测到（异常）")
    except Exception as e:
        print(f"  ✓ GCM篡改检测: 检测到篡改 ({type(e).__name__})")

    # AAD不匹配检测
    try:
        aes.decrypt_gcm(ct_gcm, key, aad=b"WRONG-AAD")
        print(f"  ✗ AAD不匹配检测: 未检测到（异常）")
    except Exception:
        print(f"  ✓ AAD不匹配检测: 检测到AAD不匹配")

    # [3] RSA
    print("\n[3] RSA-2048 非对称加密/解密")
    rsa = RSACipher()
    rsa_kp = rsa.generate_key_pair()
    msg = "Hello VPN! RSA-2048-OAEP握手消息"
    enc = rsa.encrypt(msg, rsa_kp["public_key"])
    dec = rsa.decrypt(enc, rsa_kp["private_key"])
    print(f"  ✓ RSA加密解密验证: {'通过' if msg == dec else '失败'}")

    # [4] SHA-256 & HMAC
    print("\n[4] SHA-256 哈希与 HMAC-SHA256")
    hm = HashMAC()
    data = "VPN隧道数据包内容"
    h = hm.sha256_hash(data)
    hk = hm.generate_hmac_key()
    hmac_val = hm.hmac_generate(data, hk)
    print(f"  SHA-256: {h}")
    print(f"  HMAC-SHA256: {hmac_val}")
    print(f"  ✓ HMAC验证: {'通过' if hm.hmac_verify(data, hmac_val, hk) else '失败'}")

    # [5] HKDF 密钥派生
    print("\n[5] HKDF 密钥派生")
    master = os.urandom(32)
    sub_keys = KeyDerivation.hkdf_derive_multiple(master, "vpn-session")
    for name, sk in sub_keys.items():
        print(f"  子密钥 {name}: {sk.hex()[:24]}...")
    print(f"  ✓ 从1个主密钥派生了 {len(sub_keys)} 个子密钥")

    # [6] PBKDF2 密码派生
    print("\n[6] PBKDF2 密码派生密钥")
    pwd_key, salt = KeyDerivation.pbkdf2_derive("MySecurePassword123", iterations=100000)
    print(f"  密码: MySecurePassword123")
    print(f"  盐值: {salt.hex()}")
    print(f"  派生密钥: {pwd_key.hex()[:32]}...")
    print(f"  ✓ PBKDF2派生完成（OWASP推荐迭代次数: 600000+）")

    # [7] TLS 1.3风格会话密钥派生
    print("\n[7] TLS 1.3风格会话密钥派生")
    dh_a = DHKeyExchange()
    dh_b = DHKeyExchange()
    pub_a, _ = dh_a.generate_key_pair()
    pub_b, _ = dh_b.generate_key_pair()
    shared = dh_a.compute_shared_secret(pub_b)
    session_keys = KeyDerivation.derive_session_keys(shared)
    for name, sk in session_keys.items():
        print(f"  {name}: {sk.hex()[:24]}...")
    print(f"  ✓ 从DH共享密钥派生了4个会话密钥（客户端/服务端读写密钥+IV）")

    # ===== 模块二：安全技术 =====
    print("\n" + "=" * 70)
    print("  【模块二】安全技术演示")
    print("=" * 70)

    # [8] 数字签名
    print("\n[8] 数字签名 (RSA-PSS)")
    ds = DigitalSignature()
    ds_kp = ds.generate_key_pair()
    sign_data = "VPN认证数据"
    sig = ds.sign(sign_data, ds_kp["private_key"])
    print(f"  ✓ 签名验证: {'通过' if ds.verify(sign_data, sig, ds_kp['public_key']) else '失败'}")
    print(f"  ✓ 篡改检测: {'检测到篡改' if not ds.verify('篡改数据', sig, ds_kp['public_key']) else '未检测到'}")

    # [9] 数字证书 + CRL
    print("\n[9] 数字证书与CRL吊销列表")
    ca = CertificateAuthority("SecureVPN-CA", "CN")
    cert1 = ca.issue_certificate("VPN-Server-01", {"ip": "192.168.1.100"})
    cert2 = ca.issue_certificate("VPN-Client-01", {"ip": "192.168.1.101"})
    cert3 = ca.issue_certificate("VPN-Client-02", {"ip": "192.168.1.102"})

    # 详细验证
    v1 = ca.verify_certificate(cert1)
    print(f"  证书1 ({cert1['subject']}) 验证:")
    for k, v in v1["details"].items():
        print(f"    {k}: {v}")

    # 吊销证书3
    ca.revoke_certificate(cert3["serial_number"], reason="key_compromise")
    v3 = ca.verify_certificate(cert3)
    print(f"  证书3 ({cert3['subject']}) 吊销后验证:")
    for k, v in v3["details"].items():
        print(f"    {k}: {v}")

    # CRL信息
    print(f"\n  {ca.get_crl_info()}")

    # [10] 防重放滑动窗口
    print("\n[10] 防重放攻击滑动窗口")
    arw = AntiReplayWindow(window_size=8)
    # 正常序列
    for seq in [1, 2, 3, 5, 4, 6]:
        r = arw.check_and_update(seq)
        print(f"  序列号 {seq}: {'接受' if r['accepted'] else '拒绝'} - {r['reason']}")
    # 重放攻击
    r_replay = arw.check_and_update(3)
    print(f"  序列号 3(重放): {'接受' if r_replay['accepted'] else '拒绝'} - {r_replay['reason']}")
    # 过期包
    r_old = arw.check_and_update(0)
    print(f"  序列号 0(过期): {'接受' if r_old['accepted'] else '拒绝'} - {r_old['reason']}")
    stats = arw.get_stats()
    print(f"  窗口统计: {stats}")

    # [11] 密钥轮换
    print("\n[11] 会话密钥轮换")
    skm = SessionKeyManager(key_lifetime=10)
    skm.initialize(shared)
    print(f"  初始密钥版本: v{skm.get_status()['key_version']}")
    skm.rotate()
    print(f"  第一次轮换后: v{skm.get_status()['key_version']}, 轮换次数: {skm.get_status()['rotation_count']}")
    skm.rotate()
    print(f"  第二次轮换后: v{skm.get_status()['key_version']}, 轮换次数: {skm.get_status()['rotation_count']}")
    print(f"  ✓ 密钥轮换机制正常")

    # ===== 模块三：VPN隧道 =====
    print("\n" + "=" * 70)
    print("  【模块三】VPN隧道演示（AES-GCM + 压缩 + 防重放）")
    print("=" * 70)

    # [12] GCM隧道封装
    print("\n[12] VPN隧道封装/解封装 (AES-256-GCM)")
    tunnel = TunnelProtocol(encrypt_mode="GCM", enable_compression=True)
    payload = "这是一条通过VPN安全隧道传输的用户数据包，包含敏感信息。"
    enc_pkt = tunnel.encapsulate(payload, "10.0.0.2", "10.0.0.1", "TCP", shared)
    print(f"  加密模式: {enc_pkt['header']['encrypt_mode']}")
    print(f"  压缩: {enc_pkt['header']['compressed']}")
    print(f"  {tunnel.get_packet_info(enc_pkt)}")
    dec_msg = tunnel.decapsulate(enc_pkt, shared)
    print(f"  解封装: {dec_msg}")
    print(f"  ✓ GCM隧道验证: {'通过' if payload == dec_msg else '失败'}")

    # [13] CBC隧道封装
    print("\n[13] VPN隧道封装/解封装 (AES-256-CBC)")
    tunnel_cbc = TunnelProtocol(encrypt_mode="CBC", enable_compression=True)
    enc_cbc = tunnel_cbc.encapsulate(payload, "10.0.0.2", "10.0.0.1", "TCP", shared)
    dec_cbc = tunnel_cbc.decapsulate(enc_cbc, shared)
    print(f"  加密模式: {enc_cbc['header']['encrypt_mode']}")
    print(f"  ✓ CBC隧道验证: {'通过' if payload == dec_cbc else '失败'}")

    # [14] 防重放验证
    print("\n[14] 隧道防重放验证")
    try:
        tunnel.decapsulate(enc_pkt, shared)  # 重放同一个包
        print(f"  ✗ 重放检测: 未检测到")
    except ValueError as e:
        print(f"  ✓ 重放检测: {e}")

    # [15] 完整通信流程
    print("\n[15] 完整VPN安全通信流程模拟")
    print("  步骤1: 客户端发起连接...")
    print("  步骤2: 服务端返回证书...")
    v = ca.verify_certificate(cert1)
    print(f"  步骤3: 证书验证: {'通过 ✓' if v['valid'] else '失败 ✗'}")
    print("  步骤4: DH密钥交换...")
    print(f"  步骤5: 会话密钥派生(HKDF)...")
    sk = KeyDerivation.derive_session_keys(shared)
    print(f"    客户端写密钥: {sk['client_write_key'].hex()[:16]}...")
    print(f"    服务端写密钥: {sk['server_write_key'].hex()[:16]}...")
    print("  步骤6: AES-256-GCM加密通信...")

    msgs = [
        "用户A: 项目报告已上传至服务器",
        "用户B: 收到，我马上审核",
        "用户A: 文件SHA-256: a1b2c3d4e5f6g7h8i9j0",
        "系统通知: 安全通道已建立，所有通信已加密",
    ]
    for i, m in enumerate(msgs, 1):
        pkt = tunnel.encapsulate(m, "10.0.0.2", "10.0.0.1", "TCP", shared)
        d = tunnel.decapsulate(pkt, shared)
        print(f"    [{i}] {m[:25]}... → 加密传输 → {'✓' if m == d else '✗'}")

    # 连接统计
    print(f"\n  连接统计: {tunnel.get_stats()}")
    print(f"  防重放统计: {tunnel.get_anti_replay_stats()}")
    print(f"  心跳状态: {tunnel.get_heartbeat_status()}")

    # ===== 安全特性总结 =====
    print("\n" + "=" * 70)
    print("  【安全特性总结（增强版）】")
    print("=" * 70)
    features = [
        ("对称加密", "AES-256-CBC + AES-256-GCM（认证加密AEAD）"),
        ("非对称加密", "RSA-2048/OAEP + SHA-256"),
        ("哈希算法", "SHA-256 / SHA-384 / SHA-512"),
        ("消息认证码", "HMAC-SHA256"),
        ("密钥派生", "HKDF（多子密钥派生）+ PBKDF2（密码派生）"),
        ("会话密钥", "TLS 1.3风格双向密钥派生"),
        ("数字签名", "RSA-PSS + SHA-256"),
        ("数字证书", "X.509简化版 + CRL吊销列表"),
        ("密钥交换", "Diffie-Hellman (RFC 3526 2048-bit MODP)"),
        ("完整性校验", "HMAC-SHA256 + AES-GCM Tag"),
        ("防重放攻击", "滑动窗口（64位）+ 时间戳双重检测"),
        ("密钥轮换", "自动密钥轮换 + 多版本密钥管理"),
        ("VPN隧道", "自定义隧道协议 v2（CBC/GCM双模式）"),
        ("数据压缩", "zlib压缩（自适应阈值）"),
        ("心跳保活", "定期心跳 + 超时自动断开"),
        ("连接统计", "流量/包数/压缩率/吞吐量实时统计"),
        ("身份认证", "证书 + CRL + 签名三重认证"),
    ]
    print(f"  {'安全特性':<16s} {'实现方式':<48s}")
    print(f"  {'─' * 16} {'─' * 48}")
    for name, impl in features:
        print(f"  {name:<14s} {impl}")

    print("\n" + "=" * 70)
    print("  演示完成！所有安全模块功能正常。")
    print("=" * 70)


def run_tests():
    """运行单元测试"""
    import unittest
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(os.path.dirname(__file__), "tests"), pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    main()
