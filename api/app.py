"""
FastAPI 接口层
为安全VPN系统提供 REST API 接口
"""

import os
import sys
import time
import json
import base64
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secure_vpn.crypto.aes_cipher import AESCipher, KeyDerivation
from secure_vpn.crypto.rsa_cipher import RSACipher
from secure_vpn.crypto.hash_mac import HashMAC
from secure_vpn.security.digital_signature import DigitalSignature
from secure_vpn.security.certificate import CertificateAuthority
from secure_vpn.security.key_exchange import DHKeyExchange
from secure_vpn.security.integrity import IntegrityChecker, AntiReplayWindow, SessionKeyManager
from secure_vpn.tunnel.tunnel_protocol import TunnelProtocol

app = FastAPI(title="安全VPN通信系统", version="2.0",
             description="轻量级安全VPN通信系统 - 包含密码算法、安全技术、VPN隧道")

# ==================== 全局实例 ====================
aes = AESCipher()
rsa_cipher = RSACipher()
hash_mac = HashMAC()
digital_sig = DigitalSignature()
ca = CertificateAuthority("SecureVPN-CA", "CN")
dh_exchange = DHKeyExchange()
integrity_checker = IntegrityChecker()
tunnel_gcm = TunnelProtocol(encrypt_mode="GCM", enable_compression=True)
tunnel_cbc = TunnelProtocol(encrypt_mode="CBC", enable_compression=True)

# 会话状态
session_state = {
    "shared_key": None,
    "dh_a": None,
    "dh_b": None,
    "anti_replay": AntiReplayWindow(),
    "key_manager": SessionKeyManager(),
    "rsa_keypair": None,
    "ds_keypair": None,
    "certificates": {},
    "tunnel_packets": [],
}


# ==================== 请求/响应模型 ====================

class EncryptRequest(BaseModel):
    plaintext: str

class RSAEncryptRequest(BaseModel):
    plaintext: str

class SignRequest(BaseModel):
    data: str

class VerifySignRequest(BaseModel):
    data: str
    signature: str

class HashRequest(BaseModel):
    data: str

class HMACRequest(BaseModel):
    data: str

class HKDFRequest(BaseModel):
    info: str = "vpn-session"

class PBKDF2Request(BaseModel):
    password: str
    iterations: int = 100000

class CertIssueRequest(BaseModel):
    subject: str
    days: int = 365

class CertVerifyRequest(BaseModel):
    certificate: dict

class CertRevokeRequest(BaseModel):
    serial_number: str
    reason: str = "unspecified"

class DHGenerateRequest(BaseModel):
    side: str = "client"

class DHComputeRequest(BaseModel):
    other_public_key: str

class TunnelEncapsulateRequest(BaseModel):
    payload: str
    src_ip: str = "10.0.0.2"
    dst_ip: str = "10.0.0.1"
    protocol: str = "TCP"
    mode: str = "GCM"

class ReplayCheckRequest(BaseModel):
    sequence: int


# ==================== 1. AES 加密接口 ====================

@app.get("/api/aes/generate-key")
def aes_generate_key():
    key = aes.generate_key()
    return {"key_hex": key.hex(), "key_b64": base64.b64encode(key).decode()}

@app.post("/api/aes/encrypt-cbc")
def aes_encrypt_cbc(req: EncryptRequest):
    key = aes.generate_key()
    ct = aes.encrypt_cbc(req.plaintext, key)
    return {"ciphertext": ct, "key_hex": key.hex()}

@app.post("/api/aes/decrypt-cbc")
def aes_decrypt_cbc(ciphertext: str, key_hex: str):
    key = bytes.fromhex(key_hex)
    try:
        pt = aes.decrypt_cbc(ciphertext, key)
        return {"plaintext": pt}
    except Exception as e:
        raise HTTPException(400, f"解密失败: {e}")

@app.post("/api/aes/encrypt-gcm")
def aes_encrypt_gcm(req: EncryptRequest):
    key = aes.generate_key()
    ct = aes.encrypt_gcm(req.plaintext, key)
    return {"ciphertext": ct, "key_hex": key.hex()}

@app.post("/api/aes/decrypt-gcm")
def aes_decrypt_gcm(ciphertext: str, key_hex: str, aad: str = ""):
    key = bytes.fromhex(key_hex)
    aad_bytes = aad.encode() if aad else None
    try:
        pt = aes.decrypt_gcm(ciphertext, key, aad=aad_bytes)
        return {"plaintext": pt}
    except Exception as e:
        raise HTTPException(400, f"解密失败: {e}")


# ==================== 2. RSA 加密接口 ====================

@app.get("/api/rsa/generate-keypair")
def rsa_generate_keypair():
    kp = rsa_cipher.generate_key_pair()
    pub_pem = rsa_cipher.export_public_key_pem(kp["public_key"])
    priv_pem = rsa_cipher.export_private_key_pem(kp["private_key"])
    session_state["rsa_keypair"] = kp
    return {"public_key_pem": pub_pem, "private_key_pem": priv_pem}

@app.post("/api/rsa/encrypt")
def rsa_encrypt(req: RSAEncryptRequest):
    if not session_state["rsa_keypair"]:
        rsa_generate_keypair()
    ct = rsa_cipher.encrypt(req.plaintext, session_state["rsa_keypair"]["public_key"])
    return {"ciphertext": ct}

@app.post("/api/rsa/decrypt")
def rsa_decrypt(ciphertext: str):
    if not session_state["rsa_keypair"]:
        raise HTTPException(400, "请先生成密钥对")
    try:
        pt = rsa_cipher.decrypt(ciphertext, session_state["rsa_keypair"]["private_key"])
        return {"plaintext": pt}
    except Exception as e:
        raise HTTPException(400, f"解密失败: {e}")


# ==================== 3. 哈希与HMAC接口 ====================

@app.post("/api/hash/sha256")
def sha256_hash(req: HashRequest):
    return {"hash": hash_mac.sha256_hash(req.data)}

@app.post("/api/hash/multi")
def multi_hash(req: HashRequest):
    return hash_mac.multi_hash(req.data)

@app.post("/api/hmac/generate")
def hmac_generate(req: HMACRequest):
    key = hash_mac.generate_hmac_key()
    tag = hash_mac.hmac_generate(req.data, key)
    return {"hmac": tag, "key_hex": key.hex()}

@app.post("/api/hmac/verify")
def hmac_verify(data: str, hmac_hex: str, key_hex: str):
    key = bytes.fromhex(key_hex)
    valid = hash_mac.hmac_verify(data, hmac_hex, key)
    return {"valid": valid}


# ==================== 4. 密钥派生接口 ====================

@app.post("/api/kdf/hkdf")
def hkdf_derive(req: HKDFRequest):
    master = os.urandom(32)
    keys = KeyDerivation.hkdf_derive_multiple(master, req.info)
    return {"master_key_hex": master.hex(), "sub_keys": {k: v.hex() for k, v in keys.items()}}

@app.post("/api/kdf/pbkdf2")
def pbkdf2_derive(req: PBKDF2Request):
    key, salt = KeyDerivation.pbkdf2_derive(req.password, iterations=req.iterations)
    return {"derived_key_hex": key.hex(), "salt_hex": salt.hex(), "iterations": req.iterations}

@app.get("/api/kdf/session-keys")
def derive_session_keys():
    dh_a = DHKeyExchange()
    dh_b = DHKeyExchange()
    pub_a, _ = dh_a.generate_key_pair()
    pub_b, _ = dh_b.generate_key_pair()
    shared = dh_a.compute_shared_secret(pub_b)
    keys = KeyDerivation.derive_session_keys(shared)
    return {
        "shared_secret_hex": shared.hex()[:32] + "...",
        "client_write_key": keys["client_write_key"].hex()[:24] + "...",
        "server_write_key": keys["server_write_key"].hex()[:24] + "...",
        "client_write_iv": keys["client_write_iv"].hex(),
        "server_write_iv": keys["server_write_iv"].hex(),
    }


# ==================== 5. 数字签名接口 ====================

@app.get("/api/signature/generate-keypair")
def ds_generate_keypair():
    kp = digital_sig.generate_key_pair()
    session_state["ds_keypair"] = kp
    return {"status": "密钥对已生成，可用于签名和验证"}

@app.post("/api/signature/sign")
def ds_sign(req: SignRequest):
    if not session_state["ds_keypair"]:
        ds_generate_keypair()
    sig = digital_sig.sign(req.data, session_state["ds_keypair"]["private_key"])
    return {"signature": sig, "data": req.data}

@app.post("/api/signature/verify")
def ds_verify(req: VerifySignRequest):
    if not session_state["ds_keypair"]:
        raise HTTPException(400, "请先生成密钥对")
    valid = digital_sig.verify(req.data, req.signature, session_state["ds_keypair"]["public_key"])
    return {"valid": valid, "data": req.data}


# ==================== 6. 数字证书接口 ====================

@app.post("/api/certificate/issue")
def cert_issue(req: CertIssueRequest):
    cert = ca.issue_certificate(req.subject, validity_days=req.days)
    serial = cert["serial_number"]
    session_state["certificates"][serial] = cert
    return {"serial_number": serial, "subject": cert["subject"], "info": ca.get_certificate_info(cert)}

@app.post("/api/certificate/verify")
def cert_verify(req: CertVerifyRequest):
    result = ca.verify_certificate(req.certificate)
    return result

@app.post("/api/certificate/revoke")
def cert_revoke(req: CertRevokeRequest):
    success = ca.revoke_certificate(req.serial_number, reason=req.reason)
    if not success:
        raise HTTPException(400, f"证书 {req.serial_number} 不存在")
    return {"status": "已吊销", "serial_number": req.serial_number, "reason": req.reason}

@app.get("/api/certificate/crl")
def cert_crl():
    return {"crl_info": ca.get_crl_info()}

@app.get("/api/certificate/list")
def cert_list():
    certs = []
    for serial, cert in ca.issued_certificates.items():
        certs.append({
            "serial_number": serial,
            "subject": cert["subject"],
            "revoked": cert.get("revoked", False)
        })
    return {"certificates": certs}


# ==================== 7. DH密钥交换接口 ====================

@app.post("/api/dh/generate")
def dh_generate(req: DHGenerateRequest):
    dh = DHKeyExchange()
    pub, priv = dh.generate_key_pair()
    if req.side == "client":
        session_state["dh_a"] = (dh, pub, priv)
    else:
        session_state["dh_b"] = (dh, pub, priv)
    return {"public_key": str(pub), "side": req.side}

@app.post("/api/dh/compute-shared")
def dh_compute(req: DHComputeRequest):
    other_pub = int(req.other_public_key)
    if session_state["dh_a"] and session_state["dh_b"]:
        dh_a, pub_a, priv_a = session_state["dh_a"]
        shared = dh_a.compute_shared_secret(other_pub)
        session_state["shared_key"] = shared
        return {"shared_key_hex": shared.hex()[:32] + "...", "full_hex": shared.hex()}
    raise HTTPException(400, "请先生成双方密钥对")


# ==================== 8. 防重放接口 ====================

@app.post("/api/anti-replay/check")
def replay_check(req: ReplayCheckRequest):
    result = session_state["anti_replay"].check_and_update(req.sequence)
    return result

@app.get("/api/anti-replay/stats")
def replay_stats():
    return session_state["anti_replay"].get_stats()

@app.post("/api/anti-replay/reset")
def replay_reset():
    session_state["anti_replay"] = AntiReplayWindow()
    return {"status": "已重置"}


# ==================== 9. 密钥轮换接口 ====================

@app.get("/api/key-manager/status")
def key_manager_status():
    return session_state["key_manager"].get_status()

@app.post("/api/key-manager/rotate")
def key_manager_rotate():
    if not session_state["key_manager"].current_key:
        session_state["key_manager"].initialize(os.urandom(32))
    else:
        session_state["key_manager"].rotate()
    return session_state["key_manager"].get_status()

@app.post("/api/key-manager/initialize")
def key_manager_init():
    session_state["key_manager"].initialize(os.urandom(32))
    return session_state["key_manager"].get_status()


# ==================== 10. VPN隧道接口 ====================

@app.post("/api/tunnel/encapsulate")
def tunnel_encapsulate(req: TunnelEncapsulateRequest):
    if not session_state["shared_key"]:
        # 自动执行DH交换
        dh_a = DHKeyExchange()
        dh_b = DHKeyExchange()
        pub_a, _ = dh_a.generate_key_pair()
        pub_b, _ = dh_b.generate_key_pair()
        session_state["shared_key"] = dh_a.compute_shared_secret(pub_b)

    t = tunnel_gcm if req.mode == "GCM" else tunnel_cbc
    pkt = t.encapsulate(req.payload, req.src_ip, req.dst_ip, req.protocol, session_state["shared_key"])
    session_state["tunnel_packets"].append(pkt)
    return {
        "packet_info": t.get_packet_info(pkt),
        "header": pkt["header"],
        "ciphertext_preview": pkt["encrypted_payload"][:60] + "...",
        "hmac_tag": pkt["hmac_tag"]
    }

@app.post("/api/tunnel/decapsulate")
def tunnel_decapsulate(packet: dict):
    if not session_state["shared_key"]:
        raise HTTPException(400, "请先建立共享密钥")
    try:
        t = tunnel_gcm
        payload = t.decapsulate(packet, session_state["shared_key"])
        return {"payload": payload}
    except ValueError as e:
        raise HTTPException(400, str(e))

@app.get("/api/tunnel/stats")
def tunnel_stats():
    return tunnel_gcm.get_stats()

@app.get("/api/tunnel/heartbeat")
def tunnel_heartbeat():
    return tunnel_gcm.get_heartbeat_status()

@app.get("/api/tunnel/anti-replay-stats")
def tunnel_anti_replay():
    return tunnel_gcm.get_anti_replay_stats()


# ==================== 11. 完整流程演示 ====================

@app.get("/api/demo/full-flow")
def demo_full_flow():
    """一键演示完整VPN通信流程"""
    # 1. DH密钥交换
    dh_a = DHKeyExchange()
    dh_b = DHKeyExchange()
    pub_a, _ = dh_a.generate_key_pair()
    pub_b, _ = dh_b.generate_key_pair()
    shared = dh_a.compute_shared_secret(pub_b)

    # 2. 密钥派生
    session_keys = KeyDerivation.derive_session_keys(shared)

    # 3. 隧道通信
    t = TunnelProtocol(encrypt_mode="GCM", enable_compression=True)
    messages = [
        "用户A: 项目报告已上传",
        "用户B: 收到，马上查看",
        "系统: 安全通道已建立",
    ]
    results = []
    for msg in messages:
        pkt = t.encapsulate(msg, "10.0.0.2", "10.0.0.1", "TCP", shared)
        dec = t.decapsulate(pkt, shared)
        results.append({"original": msg, "decrypted": dec, "match": msg == dec})

    return {
        "dh_shared_key_preview": shared.hex()[:32] + "...",
        "session_keys_preview": {k: v.hex()[:16] + "..." for k, v in session_keys.items()},
        "messages": results,
        "tunnel_stats": t.get_stats(),
        "anti_replay_stats": t.get_anti_replay_stats(),
    }


# ==================== 前端页面 ====================

@app.get("/", response_class=HTMLResponse)
def index():
    return HTML_CONTENT


HTML_CONTENT = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>安全VPN通信系统 - 功能演示</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#e2e8f0;--muted:#94a3b8;--accent:#3b82f6;--accent2:#10b981;--danger:#ef4444;--warn:#f59e0b}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.6}
.container{max-width:1200px;margin:0 auto;padding:20px}
h1{text-align:center;font-size:28px;margin:20px 0 5px;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.subtitle{text-align:center;color:var(--muted);margin-bottom:30px;font-size:14px}
.tabs{display:flex;gap:4px;margin-bottom:20px;flex-wrap:wrap;border-bottom:2px solid var(--border);padding-bottom:8px}
.tab{padding:8px 16px;border-radius:8px 8px 0 0;cursor:pointer;background:var(--card);color:var(--muted);border:1px solid var(--border);font-size:13px;transition:all .2s}
.tab:hover,.tab.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.panel{display:none;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:16px}
.panel.active{display:block}
.panel h3{font-size:18px;margin-bottom:16px;color:var(--accent)}
.form-row{display:flex;gap:12px;margin-bottom:12px;align-items:flex-start}
.form-row label{min-width:100px;font-size:13px;color:var(--muted);padding-top:8px}
textarea,input[type=text]{flex:1;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px 14px;color:var(--text);font-size:14px;font-family:inherit;resize:vertical}
textarea{min-height:80px}
button{padding:10px 24px;border-radius:8px;border:none;cursor:pointer;font-size:14px;font-weight:600;transition:all .2s}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#2563eb}
.btn-success{background:var(--accent2);color:#fff}
.btn-success:hover{background:#059669}
.btn-danger{background:var(--danger);color:#fff}
.btn-warn{background:var(--warn);color:#000}
.btn-sm{padding:6px 14px;font-size:12px}
.result{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;margin-top:12px;font-family:'Cascadia Code','Fira Code',monospace;font-size:13px;white-space:pre-wrap;word-break:break-all;max-height:400px;overflow-y:auto;color:#a5f3fc}
.result.error{border-color:var(--danger);color:#fca5a5}
.result.success{border-color:var(--accent2);color:#6ee7b7}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600}
.badge-ok{background:#065f46;color:#6ee7b7}
.badge-fail{background:#7f1d1d;color:#fca5a5}
.badge-info{background:#1e3a5f;color:#93c5fd}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px}
.stat-card{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px}
.stat-card .label{font-size:12px;color:var(--muted);margin-bottom:4px}
.stat-card .value{font-size:16px;font-weight:700;color:var(--accent)}
.flow-step{background:var(--bg);border-left:3px solid var(--accent);padding:10px 16px;margin-bottom:8px;border-radius:0 8px 8px 0;font-size:13px}
.flow-step .step-num{color:var(--accent);font-weight:700;margin-right:8px}
@media(max-width:768px){.two-col{grid-template-columns:1fr}.form-row{flex-direction:column}.form-row label{min-width:auto}}
</style>
</head>
<body>
<div class="container">
<h1>🔐 安全VPN通信系统</h1>
<p class="subtitle">轻量级安全VPN通信系统功能演示 — AES-GCM · RSA · 数字签名 · 数字证书 · DH密钥交换 · 防重放 · VPN隧道</p>

<div class="tabs">
<div class="tab active" onclick="showPanel('aes')">🔐 AES加密</div>
<div class="tab" onclick="showPanel('rsa')">🔑 RSA加密</div>
<div class="tab" onclick="showPanel('hash')">📝 哈希/HMAC</div>
<div class="tab" onclick="showPanel('kdf')">🧪 密钥派生</div>
<div class="tab" onclick="showPanel('sign')">✍️ 数字签名</div>
<div class="tab" onclick="showPanel('cert')">📜 数字证书</div>
<div class="tab" onclick="showPanel('dh')">🔄 DH密钥交换</div>
<div class="tab" onclick="showPanel('replay')">🛡️ 防重放</div>
<div class="tab" onclick="showPanel('keymgr')">🔑 密钥轮换</div>
<div class="tab" onclick="showPanel('tunnel')">🌐 VPN隧道</div>
<div class="tab" onclick="showPanel('flow')">🚀 完整流程</div>
</div>

<!-- AES -->
<div id="panel-aes" class="panel active">
<h3>AES-256 对称加密 (CBC / GCM)</h3>
<div class="two-col">
<div>
<h4 style="margin-bottom:8px;font-size:14px;color:var(--accent2)">CBC 模式</h4>
<div class="form-row"><label>明文</label><textarea id="aes-cbc-pt" placeholder="输入要加密的文本...">这是一条通过VPN隧道加密传输的机密消息！</textarea></div>
<div class="btn-group"><button class="btn-primary" onclick="aesCbcEncrypt()">CBC 加密</button></div>
<div id="aes-cbc-result" class="result" style="display:none"></div>
</div>
<div>
<h4 style="margin-bottom:8px;font-size:14px;color:var(--accent2)">GCM 模式（认证加密）</h4>
<div class="form-row"><label>明文</label><textarea id="aes-gcm-pt" placeholder="输入要加密的文本...">这是一条通过VPN隧道加密传输的机密消息！</textarea></div>
<div class="form-row"><label>AAD</label><input type="text" id="aes-gcm-aad" value="VPN-Tunnel-Packet-v2" placeholder="附加认证数据"></div>
<div class="btn-group"><button class="btn-primary" onclick="aesGcmEncrypt()">GCM 加密</button></div>
<div id="aes-gcm-result" class="result" style="display:none"></div>
</div>
</div>
</div>

<!-- RSA -->
<div id="panel-rsa" class="panel">
<h3>RSA-2048 非对称加密</h3>
<div class="btn-group" style="margin-bottom:16px"><button class="btn-success" onclick="rsaGenKeys()">生成RSA密钥对</button></div>
<div class="form-row"><label>明文</label><textarea id="rsa-pt" placeholder="输入要加密的文本...">Hello VPN! RSA-2048-OAEP握手消息</textarea></div>
<div class="btn-group"><button class="btn-primary" onclick="rsaEncrypt()">加密</button> <button class="btn-warn" onclick="rsaDecrypt()">解密</button></div>
<div id="rsa-result" class="result" style="display:none"></div>
</div>

<!-- Hash/HMAC -->
<div id="panel-hash" class="panel">
<h3>SHA-256 哈希与 HMAC-SHA256</h3>
<div class="two-col">
<div>
<h4 style="margin-bottom:8px;font-size:14px;color:var(--accent2)">SHA-256 哈希</h4>
<div class="form-row"><label>数据</label><textarea id="hash-data" placeholder="输入数据...">VPN隧道数据包内容</textarea></div>
<div class="btn-group"><button class="btn-primary" onclick="sha256Hash()">计算哈希</button> <button class="btn-success" onclick="multiHash()">多算法对比</button></div>
<div id="hash-result" class="result" style="display:none"></div>
</div>
<div>
<h4 style="margin-bottom:8px;font-size:14px;color:var(--accent2)">HMAC-SHA256</h4>
<div class="form-row"><label>数据</label><textarea id="hmac-data" placeholder="输入数据...">VPN隧道数据包内容</textarea></div>
<div class="btn-group"><button class="btn-primary" onclick="hmacGenerate()">生成HMAC</button></div>
<div id="hmac-result" class="result" style="display:none"></div>
</div>
</div>
</div>

<!-- KDF -->
<div id="panel-kdf" class="panel">
<h3>密钥派生函数</h3>
<div class="two-col">
<div>
<h4 style="margin-bottom:8px;font-size:14px;color:var(--accent2)">HKDF 密钥派生</h4>
<div class="form-row"><label>上下文信息</label><input type="text" id="hkdf-info" value="vpn-session"></div>
<div class="btn-group"><button class="btn-primary" onclick="hkdfDerive()">派生子密钥</button></div>
<div id="hkdf-result" class="result" style="display:none"></div>
</div>
<div>
<h4 style="margin-bottom:8px;font-size:14px;color:var(--accent2)">PBKDF2 密码派生</h4>
<div class="form-row"><label>密码</label><input type="text" id="pbkdf2-pwd" value="MySecurePassword123"></div>
<div class="form-row"><label>迭代次数</label><input type="text" id="pbkdf2-iter" value="100000"></div>
<div class="btn-group"><button class="btn-primary" onclick="pbkdf2Derive()">派生密钥</button></div>
<div id="pbkdf2-result" class="result" style="display:none"></div>
</div>
</div>
<div style="margin-top:16px">
<h4 style="margin-bottom:8px;font-size:14px;color:var(--accent2)">TLS 1.3 风格会话密钥派生</h4>
<div class="btn-group"><button class="btn-success" onclick="sessionKeysDerive()">一键派生会话密钥</button></div>
<div id="session-keys-result" class="result" style="display:none"></div>
</div>
</div>

<!-- 数字签名 -->
<div id="panel-sign" class="panel">
<h3>RSA-PSS 数字签名</h3>
<div class="btn-group" style="margin-bottom:16px"><button class="btn-success" onclick="dsGenKeys()">生成签名密钥对</button></div>
<div class="form-row"><label>待签名数据</label><textarea id="sign-data" placeholder="输入要签名的数据...">VPN认证数据 - 身份确认</textarea></div>
<div class="btn-group"><button class="btn-primary" onclick="dsSign()">签名</button> <button class="btn-warn" onclick="dsVerify()">验证签名</button> <button class="btn-danger" onclick="dsTamperVerify()">篡改后验证</button></div>
<div id="sign-result" class="result" style="display:none"></div>
</div>

<!-- 数字证书 -->
<div id="panel-cert" class="panel">
<h3>数字证书与CRL吊销列表</h3>
<div class="form-row"><label>证书主题</label><input type="text" id="cert-subject" value="VPN-Server-01"></div>
<div class="btn-group">
<button class="btn-primary" onclick="certIssue()">签发证书</button>
<button class="btn-warn" onclick="certList()">查看所有证书</button>
<button class="btn-danger" onclick="certRevokeLast()">吊销最后签发的证书</button>
<button class="btn-success" onclick="certShowCRL()">查看CRL</button>
</div>
<div id="cert-result" class="result" style="display:none"></div>
</div>

<!-- DH -->
<div id="panel-dh" class="panel">
<h3>Diffie-Hellman 密钥交换</h3>
<div class="btn-group" style="margin-bottom:16px">
<button class="btn-primary" onclick="dhGenClient()">生成客户端密钥</button>
<button class="btn-primary" onclick="dhGenServer()">生成服务端密钥</button>
<button class="btn-success" onclick="dhCompute()">计算共享密钥</button>
</div>
<div id="dh-result" class="result" style="display:none"></div>
</div>

<!-- 防重放 -->
<div id="panel-replay" class="panel">
<h3>防重放攻击滑动窗口</h3>
<div class="form-row"><label>序列号</label><input type="text" id="replay-seq" value="1" placeholder="输入序列号"></div>
<div class="btn-group">
<button class="btn-primary" onclick="replayCheck()">检查序列号</button>
<button class="btn-success" onclick="replayBatch()">批量测试(乱序)</button>
<button class="btn-danger" onclick="replayAttack()">模拟重放攻击</button>
<button class="btn-warn" onclick="replayReset()">重置窗口</button>
</div>
<div id="replay-result" class="result" style="display:none"></div>
</div>

<!-- 密钥轮换 -->
<div id="panel-keymgr" class="panel">
<h3>会话密钥轮换</h3>
<div class="btn-group" style="margin-bottom:16px">
<button class="btn-success" onclick="kmInit()">初始化密钥</button>
<button class="btn-primary" onclick="kmRotate()">轮换密钥</button>
<button class="btn-warn" onclick="kmStatus()">查看状态</button>
</div>
<div id="keymgr-result" class="result" style="display:none"></div>
</div>

<!-- VPN隧道 -->
<div id="panel-tunnel" class="panel">
<h3>VPN隧道封装/解封装</h3>
<div class="two-col">
<div>
<div class="form-row"><label>载荷</label><textarea id="tunnel-payload" placeholder="输入要封装的数据...">这是一条通过VPN安全隧道传输的用户数据包</textarea></div>
<div class="form-row"><label>源IP</label><input type="text" id="tunnel-src" value="10.0.0.2"></div>
<div class="form-row"><label>目的IP</label><input type="text" id="tunnel-dst" value="10.0.0.1"></div>
<div class="form-row"><label>加密模式</label>
<div class="btn-group"><button class="btn-primary btn-sm" onclick="tunnelEnc('GCM')">GCM</button> <button class="btn-warn btn-sm" onclick="tunnelEnc('CBC')">CBC</button></div>
</div>
</div>
<div>
<h4 style="margin-bottom:8px;font-size:14px;color:var(--accent2)">隧道状态</h4>
<div class="btn-group" style="margin-bottom:12px"><button class="btn-success" onclick="tunnelStats()">查看统计</button></div>
<div id="tunnel-result" class="result" style="display:none"></div>
</div>
</div>
</div>

<!-- 完整流程 -->
<div id="panel-flow" class="panel">
<h3>🚀 一键演示完整VPN安全通信流程</h3>
<div class="btn-group" style="margin-bottom:20px"><button class="btn-success" onclick="runFullFlow()" style="padding:14px 32px;font-size:16px">▶ 运行完整演示</button></div>
<div id="flow-result" class="result" style="display:none"></div>
</div>

</div>

<script>
const API = '';
let rsaKeys = false, dsKeys = false, dhClient = null, dhServer = null;
let lastCertSerial = null;

function showPanel(id) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('panel-' + id).classList.add('active');
  event.target.classList.add('active');
}

async function api(url, method='GET', body=null) {
  const opts = {method, headers:{'Content-Type':'application/json'}};
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(API + url, opts);
  if (!r.ok) { const e = await r.json(); throw new Error(e.detail || '请求失败'); }
  return r.json();
}

function showResult(id, data, isError=false) {
  const el = document.getElementById(id);
  el.style.display = 'block';
  el.className = 'result' + (isError ? ' error' : ' success');
  el.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
}

// ==================== AES ====================
async function aesCbcEncrypt() {
  try {
    const r = await api('/api/aes/encrypt-cbc', 'POST', {plaintext: document.getElementById('aes-cbc-pt').value});
    showResult('aes-cbc-result', '✅ CBC加密成功\\n\\n密钥: ' + r.key_hex.substring(0,32) + '...\\n密文: ' + r.ciphertext.substring(0,64) + '...');
  } catch(e) { showResult('aes-cbc-result', '❌ ' + e.message, true); }
}

async function aesGcmEncrypt() {
  try {
    const r = await api('/api/aes/encrypt-gcm', 'POST', {plaintext: document.getElementById('aes-gcm-pt').value});
    showResult('aes-gcm-result', '✅ GCM加密成功\\n\\n密钥: ' + r.key_hex.substring(0,32) + '...\\n密文: ' + r.ciphertext.substring(0,64) + '...');
  } catch(e) { showResult('aes-gcm-result', '❌ ' + e.message, true); }
}

// ==================== RSA ====================
async function rsaGenKeys() {
  try {
    const r = await api('/api/rsa/generate-keypair');
    rsaKeys = true;
    showResult('rsa-result', '✅ RSA-2048密钥对已生成\\n\\n公钥:\\n' + r.public_key_pem.substring(0,100) + '...');
  } catch(e) { showResult('rsa-result', '❌ ' + e.message, true); }
}

async function rsaEncrypt() {
  try {
    if (!rsaKeys) await rsaGenKeys();
    const r = await api('/api/rsa/encrypt', 'POST', {plaintext: document.getElementById('rsa-pt').value});
    showResult('rsa-result', '✅ RSA加密成功\\n\\n密文: ' + r.ciphertext.substring(0,64) + '...');
  } catch(e) { showResult('rsa-result', '❌ ' + e.message, true); }
}

async function rsaDecrypt() {
  try {
    if (!rsaKeys) throw new Error('请先生成密钥对');
    const encResult = JSON.parse(document.getElementById('rsa-result').textContent);
    // 需要先加密才能解密
    const r = await api('/api/rsa/encrypt', 'POST', {plaintext: document.getElementById('rsa-pt').value});
    const d = await api('/api/rsa/decrypt', 'POST', r.ciphertext);
    showResult('rsa-result', '✅ RSA解密成功\\n\\n原文: ' + d.plaintext);
  } catch(e) { showResult('rsa-result', '❌ ' + e.message, true); }
}

// ==================== Hash/HMAC ====================
async function sha256Hash() {
  try {
    const r = await api('/api/hash/sha256', 'POST', {data: document.getElementById('hash-data').value});
    showResult('hash-result', '✅ SHA-256: ' + r.hash);
  } catch(e) { showResult('hash-result', '❌ ' + e.message, true); }
}

async function multiHash() {
  try {
    const r = await api('/api/hash/multi', 'POST', {data: document.getElementById('hash-data').value});
    let s = '✅ 多算法哈希对比\\n\\n';
    for (const [k,v] of Object.entries(r)) s += k + ': ' + v + '\\n';
    showResult('hash-result', s);
  } catch(e) { showResult('hash-result', '❌ ' + e.message, true); }
}

async function hmacGenerate() {
  try {
    const r = await api('/api/hmac/generate', 'POST', {data: document.getElementById('hmac-data').value});
    showResult('hmac-result', '✅ HMAC-SHA256生成成功\\n\\nHMAC: ' + r.hmac + '\\n密钥: ' + r.key_hex.substring(0,32) + '...');
  } catch(e) { showResult('hmac-result', '❌ ' + e.message, true); }
}

// ==================== KDF ====================
async function hkdfDerive() {
  try {
    const r = await api('/api/kdf/hkdf', 'POST', {info: document.getElementById('hkdf-info').value});
    let s = '✅ HKDF密钥派生成功\\n\\n主密钥: ' + r.master_key_hex.substring(0,32) + '...\\n\\n子密钥:\\n';
    for (const [k,v] of Object.entries(r.sub_keys)) s += '  ' + k + ': ' + v + '\\n';
    showResult('hkdf-result', s);
  } catch(e) { showResult('hkdf-result', '❌ ' + e.message, true); }
}

async function pbkdf2Derive() {
  try {
    const r = await api('/api/kdf/pbkdf2', 'POST', {password: document.getElementById('pbkdf2-pwd').value, iterations: parseInt(document.getElementById('pbkdf2-iter').value)});
    showResult('pbkdf2-result', '✅ PBKDF2密钥派生成功\\n\\n派生密钥: ' + r.derived_key_hex.substring(0,32) + '...\\n盐值: ' + r.salt_hex + '\\n迭代次数: ' + r.iterations);
  } catch(e) { showResult('pbkdf2-result', '❌ ' + e.message, true); }
}

async function sessionKeysDerive() {
  try {
    const r = await api('/api/kdf/session-keys');
    let s = '✅ TLS 1.3风格会话密钥派生\\n\\n共享密钥: ' + r.dh_shared_key_preview + '\\n\\n';
    for (const [k,v] of Object.entries(r.session_keys_preview)) s += k + ': ' + v + '\\n';
    showResult('session-keys-result', s);
  } catch(e) { showResult('session-keys-result', '❌ ' + e.message, true); }
}

// ==================== 数字签名 ====================
async function dsGenKeys() {
  try {
    await api('/api/signature/generate-keypair');
    dsKeys = true;
    showResult('sign-result', '✅ RSA-PSS签名密钥对已生成');
  } catch(e) { showResult('sign-result', '❌ ' + e.message, true); }
}

async function dsSign() {
  try {
    if (!dsKeys) await dsGenKeys();
    const r = await api('/api/signature/sign', 'POST', {data: document.getElementById('sign-data').value});
    window._lastSignature = r.signature;
    window._lastSignData = r.data;
    showResult('sign-result', '✅ 签名成功\\n\\n原文: ' + r.data + '\\n签名: ' + r.signature.substring(0,64) + '...');
  } catch(e) { showResult('sign-result', '❌ ' + e.message, true); }
}

async function dsVerify() {
  try {
    const r = await api('/api/signature/verify', 'POST', {data: window._lastSignData, signature: window._lastSignature});
    showResult('sign-result', (r.valid ? '✅' : '❌') + ' 签名验证: ' + (r.valid ? '通过 — 数据完整且来源可信' : '失败'));
  } catch(e) { showResult('sign-result', '❌ ' + e.message, true); }
}

async function dsTamperVerify() {
  try {
    const r = await api('/api/signature/verify', 'POST', {data: '篡改后的数据!!!', signature: window._lastSignature});
    showResult('sign-result', (r.valid ? '❌' : '✅') + ' 篡改检测: ' + (r.valid ? '未检测到篡改（异常）' : '成功检测到数据篡改！签名验证失败'));
  } catch(e) { showResult('sign-result', '❌ ' + e.message, true); }
}

// ==================== 证书 ====================
async function certIssue() {
  try {
    const r = await api('/api/certificate/issue', 'POST', {subject: document.getElementById('cert-subject').value});
    lastCertSerial = r.serial_number;
    showResult('cert-result', '✅ 证书签发成功\\n\\n' + r.info);
  } catch(e) { showResult('cert-result', '❌ ' + e.message, true); }
}

async function certList() {
  try {
    const r = await api('/api/certificate/list');
    let s = '📋 已签发证书列表\\n\\n';
    r.certificates.forEach(c => {
      s += (c.revoked ? '❌' : '✅') + ' ' + c.serial_number + ' | ' + c.subject + (c.revoked ? ' [已吊销]' : '') + '\\n';
    });
    showResult('cert-result', s);
  } catch(e) { showResult('cert-result', '❌ ' + e.message, true); }
}

async function certRevokeLast() {
  try {
    if (!lastCertSerial) throw new Error('请先签发证书');
    const r = await api('/api/certificate/revoke', 'POST', {serial_number: lastCertSerial, reason: 'key_compromise'});
    showResult('cert-result', '✅ 证书已吊销: ' + r.serial_number + '\\n原因: ' + r.reason);
  } catch(e) { showResult('cert-result', '❌ ' + e.message, true); }
}

async function certShowCRL() {
  try {
    const r = await api('/api/certificate/crl');
    showResult('cert-result', r.crl_info);
  } catch(e) { showResult('cert-result', '❌ ' + e.message, true); }
}

// ==================== DH ====================
async function dhGenClient() {
  try {
    const r = await api('/api/dh/generate', 'POST', {side: 'client'});
    dhClient = r.public_key;
    showResult('dh-result', '✅ 客户端DH密钥已生成\\n\\n客户端公钥: ' + r.public_key.substring(0,48) + '...');
  } catch(e) { showResult('dh-result', '❌ ' + e.message, true); }
}

async function dhGenServer() {
  try {
    const r = await api('/api/dh/generate', 'POST', {side: 'server'});
    dhServer = r.public_key;
    showResult('dh-result', '✅ 服务端DH密钥已生成\\n\\n服务端公钥: ' + r.public_key.substring(0,48) + '...');
  } catch(e) { showResult('dh-result', '❌ ' + e.message, true); }
}

async function dhCompute() {
  try {
    if (!dhClient || !dhServer) throw new Error('请先生成双方密钥');
    const r = await api('/api/dh/compute-shared', 'POST', {other_public_key: dhServer});
    showResult('dh-result', '✅ DH密钥交换完成！\\n\\n共享密钥: ' + r.full_hex + '\\n\\n双方计算出相同的密钥，即使攻击者截获公钥也无法推导');
  } catch(e) { showResult('dh-result', '❌ ' + e.message, true); }
}

// ==================== 防重放 ====================
async function replayCheck() {
  try {
    const seq = parseInt(document.getElementById('replay-seq').value);
    const r = await api('/api/anti-replay/check', 'POST', {sequence: seq});
    const icon = r.accepted ? '✅' : '🛡️';
    showResult('replay-result', icon + ' 序列号 ' + seq + ': ' + (r.accepted ? '接受' : '拒绝') + ' — ' + r.reason + '\\n\\n' + JSON.stringify(api('/api/anti-replay/stats').then(r=>r), null, 2));
    // 同时获取统计
    const stats = await api('/api/anti-replay/stats');
    showResult('replay-result', icon + ' 序列号 ' + seq + ': ' + (r.accepted ? '接受' : '拒绝') + ' — ' + r.reason);
  } catch(e) { showResult('replay-result', '❌ ' + e.message, true); }
}

async function replayBatch() {
  try {
    await api('/api/anti-replay/reset', 'POST');
    const seqs = [3, 1, 7, 2, 5, 4, 6];
    let s = '📦 批量测试（乱序序列）\\n\\n';
    for (const seq of seqs) {
      const r = await api('/api/anti-replay/check', 'POST', {sequence: seq});
      s += (r.accepted ? '✅' : '🛡️') + ' seq=' + seq + ': ' + r.reason + '\\n';
    }
    // 重放测试
    const r2 = await api('/api/anti-replay/check', 'POST', {sequence: 3});
    s += '\\n🛡️ seq=3(重放): ' + r2.reason;
    showResult('replay-result', s);
  } catch(e) { showResult('replay-result', '❌ ' + e.message, true); }
}

async function replayAttack() {
  try {
    await api('/api/anti-replay/reset', 'POST');
    await api('/api/anti-replay/check', 'POST', {sequence: 1});
    await api('/api/anti-replay/check', 'POST', {sequence: 2});
    const r = await api('/api/anti-replay/check', 'POST', {sequence: 1});
    showResult('replay-result', '🛡️ 模拟重放攻击\\n\\n✅ seq=1: 首次接收\\n✅ seq=2: 首次接收\\n🛡️ seq=1(重放): ' + r.reason);
  } catch(e) { showResult('replay-result', '❌ ' + e.message, true); }
}

async function replayReset() {
  try {
    await api('/api/anti-replay/reset', 'POST');
    showResult('replay-result', '✅ 滑动窗口已重置');
  } catch(e) { showResult('replay-result', '❌ ' + e.message, true); }
}

// ==================== 密钥轮换 ====================
async function kmInit() {
  try {
    const r = await api('/api/key-manager/initialize', 'POST');
    showResult('keymgr-result', '✅ 密钥已初始化\\n\\n' + JSON.stringify(r, null, 2));
  } catch(e) { showResult('keymgr-result', '❌ ' + e.message, true); }
}

async function kmRotate() {
  try {
    const r = await api('/api/key-manager/rotate', 'POST');
    showResult('keymgr-result', '✅ 密钥已轮换\\n\\n' + JSON.stringify(r, null, 2));
  } catch(e) { showResult('keymgr-result', '❌ ' + e.message, true); }
}

async function kmStatus() {
  try {
    const r = await api('/api/key-manager/status');
    showResult('keymgr-result', '📋 密钥管理器状态\\n\\n' + JSON.stringify(r, null, 2));
  } catch(e) { showResult('keymgr-result', '❌ ' + e.message, true); }
}

// ==================== VPN隧道 ====================
async function tunnelEnc(mode) {
  try {
    const r = await api('/api/tunnel/encapsulate', 'POST', {
      payload: document.getElementById('tunnel-payload').value,
      src_ip: document.getElementById('tunnel-src').value,
      dst_ip: document.getElementById('tunnel-dst').value,
      mode: mode
    });
    let s = '✅ 隧道封装成功 (' + mode + ' 模式)\\n\\n' + r.packet_info + '\\n\\n';
    s += '头部信息:\\n';
    s += '  加密模式: ' + r.header.encrypt_mode + '\\n';
    s += '  压缩: ' + (r.header.compressed ? '是' : '否') + '\\n';
    s += '  序列号: ' + r.header.sequence + '\\n';
    s += '  标志位: 0x' + r.header.flags.toString(16) + '\\n\\n';
    s += '密文预览: ' + r.ciphertext_preview + '\\n';
    s += 'HMAC标签: ' + r.hmac_tag;
    showResult('tunnel-result', s);
  } catch(e) { showResult('tunnel-result', '❌ ' + e.message, true); }
}

async function tunnelStats() {
  try {
    const r = await api('/api/tunnel/stats');
    showResult('tunnel-result', '📊 隧道统计\\n\\n' + JSON.stringify(r, null, 2));
  } catch(e) { showResult('tunnel-result', '❌ ' + e.message, true); }
}

// ==================== 完整流程 ====================
async function runFullFlow() {
  try {
    const r = await api('/api/demo/full-flow');
    let s = '🚀 完整VPN安全通信流程演示\\n\\n';
    s += '━━━ 步骤1: DH密钥交换 ━━━\\n';
    s += '共享密钥: ' + r.dh_shared_key_preview + '\\n\\n';
    s += '━━━ 步骤2: TLS 1.3 密钥派生 ━━━\\n';
    for (const [k,v] of Object.entries(r.session_keys_preview)) s += '  ' + k + ': ' + v + '\\n';
    s += '\\n━━━ 步骤3: AES-256-GCM 加密通信 ━━━\\n';
    r.messages.forEach((m, i) => {
      s += '  [' + (i+1) + '] ' + (m.match ? '✅' : '❌') + ' ' + m.original + '\\n';
    });
    s += '\\n━━━ 步骤4: 连接统计 ━━━\\n';
    s += '  发送包数: ' + r.tunnel_stats.packets_sent + '\\n';
    s += '  接收包数: ' + r.tunnel_stats.packets_received + '\\n';
    s += '  总字节数: ' + r.tunnel_stats.total_bytes + '\\n';
    s += '\\n━━━ 步骤5: 防重放统计 ━━━\\n';
    s += '  窗口范围: ' + r.anti_replay_stats.window_range + '\\n';
    s += '  重放检测: ' + r.anti_replay_stats.replay_detected + ' 次\\n';
    s += '\\n✅ 全部流程演示完成！';
    showResult('flow-result', s);
  } catch(e) { showResult('flow-result', '❌ ' + e.message, true); }
}
</script>
</body>
</html>"""


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
