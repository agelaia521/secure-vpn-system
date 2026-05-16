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

from crypto.aes_cipher import AESCipher, KeyDerivation
from crypto.rsa_cipher import RSACipher
from crypto.hash_mac import HashMAC
from security.digital_signature import DigitalSignature
from security.certificate import CertificateAuthority
from security.key_exchange import DHKeyExchange
from security.integrity import IntegrityChecker, AntiReplayWindow, SessionKeyManager
from tunnel.tunnel_protocol import TunnelProtocol

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
<title>Secure VPN System</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
::-webkit-scrollbar { display: none; }
html { -ms-overflow-style: none; scrollbar-width: none; }

:root {
  --bg: #ffffff;
  --bg-secondary: #f6f8fa;
  --border: #d0d7de;
  --text: #24292f;
  --text-muted: #57606a;
  --accent: #0969da;
  --accent-hover: #0550ae;
  --success: #1a7f37;
  --error: #cf222e;
  --code-bg: #f6f8fa;
  --code-text: #24292f;
}

body {
  font-family: 'Roboto', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
  font-size: 14px;
}

.tabs {
  display: flex;
  gap: 0;
  border-bottom: 1px solid var(--border);
  overflow-x: auto;
  background: var(--bg-secondary);
}

.tab {
  padding: 10px 16px;
  cursor: pointer;
  color: var(--text-muted);
  font-size: 13px;
  white-space: nowrap;
  border: 1px solid transparent;
  border-bottom: 2px solid transparent;
  background: transparent;
  transition: all 0.2s ease;
}

.tab:hover {
  color: var(--text);
}

.tab.active {
  color: var(--accent);
  border-bottom-color: var(--accent);
  background: var(--bg);
}

.panels {
  padding: 16px;
}

.panel {
  display: none;
}

.panel.active {
  display: block;
}

.panel-title {
  font-size: 15px;
  font-weight: 500;
  margin-bottom: 8px;
  color: var(--text);
}

.panel-desc {
  font-size: 12px;
  color: var(--text-muted);
  margin-bottom: 16px;
}

.form-row {
  margin-bottom: 12px;
}

.form-row label {
  display: block;
  font-size: 12px;
  color: var(--text-muted);
  margin-bottom: 4px;
}

textarea,
input[type="text"] {
  width: 100%;
  background: var(--bg);
  border: 1px solid var(--border);
  padding: 8px 12px;
  font-size: 13px;
  font-family: 'Roboto', monospace;
  color: var(--text);
  outline: none;
  transition: border-color 0.2s ease;
}

textarea:focus,
input[type="text"]:focus {
  border-color: var(--accent);
}

textarea {
  min-height: 70px;
  resize: vertical;
}

.btn-group {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}

.btn {
  padding: 6px 12px;
  font-size: 13px;
  cursor: pointer;
  background: transparent;
  border: none;
  color: var(--accent);
  transition: color 0.2s ease;
}

.btn:hover {
  color: var(--accent-hover);
}

.result-container {
  position: relative;
  margin-top: 12px;
}

.result {
  background: var(--code-bg);
  border: 1px solid var(--border);
  padding: 12px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--code-text);
  max-height: 300px;
  overflow-y: auto;
}

.result.error {
  border-color: var(--error);
}

.result.success {
  border-color: var(--success);
}

.copy-btn {
  position: absolute;
  top: 6px;
  right: 6px;
  padding: 4px 8px;
  font-size: 11px;
  background: var(--bg);
  border: 1px solid var(--border);
  cursor: pointer;
  opacity: 0;
  transition: opacity 0.2s ease;
}

.result-container:hover .copy-btn {
  opacity: 1;
}

.copy-btn:hover {
  border-color: var(--accent);
  color: var(--accent);
}

.toast {
  position: fixed;
  bottom: 20px;
  left: 50%;
  transform: translateX(-50%) translateY(100px);
  background: var(--text);
  color: var(--bg);
  padding: 8px 16px;
  font-size: 12px;
  opacity: 0;
  transition: all 0.2s ease;
}

.toast.show {
  transform: translateX(-50%) translateY(0);
  opacity: 1;
}

.two-col {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.col {
  border: 1px solid var(--border);
  padding: 12px;
}

.col-title {
  font-size: 13px;
  font-weight: 500;
  margin-bottom: 12px;
  color: var(--text-muted);
}

@media(max-width:768px) {
  .two-col { grid-template-columns: 1fr; }
}
</style>
</head>
<body>
<div class="tabs">
<div class="tab active" onclick="showPanel('aes-cbc')">AES-CBC</div>
<div class="tab" onclick="showPanel('aes-gcm')">AES-GCM</div>
<div class="tab" onclick="showPanel('rsa')">RSA</div>
<div class="tab" onclick="showPanel('hash')">SHA-256</div>
<div class="tab" onclick="showPanel('hmac')">HMAC</div>
<div class="tab" onclick="showPanel('hkdf')">HKDF</div>
<div class="tab" onclick="showPanel('pbkdf2')">PBKDF2</div>
<div class="tab" onclick="showPanel('sign')">数字签名</div>
<div class="tab" onclick="showPanel('cert')">数字证书</div>
<div class="tab" onclick="showPanel('crl')">CRL</div>
<div class="tab" onclick="showPanel('dh')">DH密钥交换</div>
<div class="tab" onclick="showPanel('replay')">防重放</div>
<div class="tab" onclick="showPanel('keymgr')">密钥轮换</div>
<div class="tab" onclick="showPanel('tunnel-gcm')">GCM隧道</div>
<div class="tab" onclick="showPanel('tunnel-cbc')">CBC隧道</div>
<div class="tab" onclick="showPanel('flow')">完整流程</div>
</div>

<div class="panels">

<!-- AES-CBC -->
<div id="panel-aes-cbc" class="panel active">
<div class="panel-title">AES-256-CBC 加密</div>
<div class="panel-desc">CBC模式对称加密，使用随机IV</div>
<div class="form-row">
<label>明文</label>
<textarea id="aes-cbc-pt">这是一条通过VPN隧道加密传输的机密消息！</textarea>
</div>
<div class="btn-group">
<button class="btn" onclick="aesCbcEncrypt()">加密</button>
</div>
<div class="result-container">
<div id="aes-cbc-result" class="result" style="display:none"></div>
<button class="copy-btn" onclick="copyResult('aes-cbc-result')">复制</button>
</div>
</div>

<!-- AES-GCM -->
<div id="panel-aes-gcm" class="panel">
<div class="panel-title">AES-256-GCM 认证加密</div>
<div class="panel-desc">GCM模式提供加密和完整性认证</div>
<div class="form-row">
<label>明文</label>
<textarea id="aes-gcm-pt">这是一条通过VPN隧道加密传输的机密消息！</textarea>
</div>
<div class="form-row">
<label>AAD（附加认证数据）</label>
<input type="text" id="aes-gcm-aad" value="VPN-Tunnel-Packet-v2">
</div>
<div class="btn-group">
<button class="btn" onclick="aesGcmEncrypt()">加密</button>
</div>
<div class="result-container">
<div id="aes-gcm-result" class="result" style="display:none"></div>
<button class="copy-btn" onclick="copyResult('aes-gcm-result')">复制</button>
</div>
</div>

<!-- RSA -->
<div id="panel-rsa" class="panel">
<div class="panel-title">RSA-2048 非对称加密</div>
<div class="panel-desc">使用OAEP填充的RSA加密</div>
<div class="btn-group">
<button class="btn" onclick="rsaGenKeys()">生成密钥对</button>
</div>
<div class="form-row">
<label>明文</label>
<textarea id="rsa-pt">Hello VPN! RSA-2048-OAEP握手消息</textarea>
</div>
<div class="btn-group">
<button class="btn" onclick="rsaEncrypt()">加密</button>
<button class="btn" onclick="rsaDecrypt()">解密</button>
</div>
<div class="result-container">
<div id="rsa-result" class="result" style="display:none"></div>
<button class="copy-btn" onclick="copyResult('rsa-result')">复制</button>
</div>
</div>

<!-- SHA-256 -->
<div id="panel-hash" class="panel">
<div class="panel-title">SHA-256 哈希</div>
<div class="panel-desc">计算消息的SHA-256哈希值</div>
<div class="form-row">
<label>数据</label>
<textarea id="hash-data">VPN隧道数据包内容</textarea>
</div>
<div class="btn-group">
<button class="btn" onclick="sha256Hash()">计算哈希</button>
<button class="btn" onclick="multiHash()">多算法</button>
</div>
<div class="result-container">
<div id="hash-result" class="result" style="display:none"></div>
<button class="copy-btn" onclick="copyResult('hash-result')">复制</button>
</div>
</div>

<!-- HMAC -->
<div id="panel-hmac" class="panel">
<div class="panel-title">HMAC-SHA256 消息认证</div>
<div class="panel-desc">使用密钥生成消息认证码</div>
<div class="form-row">
<label>数据</label>
<textarea id="hmac-data">VPN隧道数据包内容</textarea>
</div>
<div class="btn-group">
<button class="btn" onclick="hmacGenerate()">生成HMAC</button>
</div>
<div class="result-container">
<div id="hmac-result" class="result" style="display:none"></div>
<button class="copy-btn" onclick="copyResult('hmac-result')">复制</button>
</div>
</div>

<!-- HKDF -->
<div id="panel-hkdf" class="panel">
<div class="panel-title">HKDF 密钥派生</div>
<div class="panel-desc">从主密钥派生出多个子密钥</div>
<div class="form-row">
<label>上下文信息</label>
<input type="text" id="hkdf-info" value="vpn-session">
</div>
<div class="btn-group">
<button class="btn" onclick="hkdfDerive()">派生</button>
</div>
<div class="result-container">
<div id="hkdf-result" class="result" style="display:none"></div>
<button class="copy-btn" onclick="copyResult('hkdf-result')">复制</button>
</div>
</div>

<!-- PBKDF2 -->
<div id="panel-pbkdf2" class="panel">
<div class="panel-title">PBKDF2 密码派生</div>
<div class="panel-desc">从密码安全地派生出加密密钥</div>
<div class="form-row">
<label>密码</label>
<input type="text" id="pbkdf2-pwd" value="MySecurePassword123">
</div>
<div class="form-row">
<label>迭代次数</label>
<input type="text" id="pbkdf2-iter" value="100000">
</div>
<div class="btn-group">
<button class="btn" onclick="pbkdf2Derive()">派生</button>
</div>
<div class="result-container">
<div id="pbkdf2-result" class="result" style="display:none"></div>
<button class="copy-btn" onclick="copyResult('pbkdf2-result')">复制</button>
</div>
</div>

<!-- 数字签名 -->
<div id="panel-sign" class="panel">
<div class="panel-title">RSA-PSS 数字签名</div>
<div class="panel-desc">使用私钥签名，公钥验证</div>
<div class="btn-group">
<button class="btn" onclick="dsGenKeys()">生成密钥</button>
</div>
<div class="form-row">
<label>数据</label>
<textarea id="sign-data">VPN认证数据 - 身份确认</textarea>
</div>
<div class="btn-group">
<button class="btn" onclick="dsSign()">签名</button>
<button class="btn" onclick="dsVerify()">验证</button>
<button class="btn" onclick="dsTamperVerify()">篡改验证</button>
</div>
<div class="result-container">
<div id="sign-result" class="result" style="display:none"></div>
<button class="copy-btn" onclick="copyResult('sign-result')">复制</button>
</div>
</div>

<!-- 数字证书 -->
<div id="panel-cert" class="panel">
<div class="panel-title">X.509 数字证书</div>
<div class="panel-desc">CA签发和验证数字证书</div>
<div class="form-row">
<label>证书主题</label>
<input type="text" id="cert-subject" value="VPN-Server-01">
</div>
<div class="btn-group">
<button class="btn" onclick="certIssue()">签发</button>
<button class="btn" onclick="certList()">列表</button>
<button class="btn" onclick="certRevokeLast()">吊销</button>
</div>
<div class="result-container">
<div id="cert-result" class="result" style="display:none"></div>
<button class="copy-btn" onclick="copyResult('cert-result')">复制</button>
</div>
</div>

<!-- CRL -->
<div id="panel-crl" class="panel">
<div class="panel-title">CRL 证书吊销列表</div>
<div class="panel-desc">管理已吊销的证书</div>
<div class="btn-group">
<button class="btn" onclick="certShowCRL()">查看CRL</button>
</div>
<div class="result-container">
<div id="crl-result" class="result" style="display:none"></div>
<button class="copy-btn" onclick="copyResult('crl-result')">复制</button>
</div>
</div>

<!-- DH密钥交换 -->
<div id="panel-dh" class="panel">
<div class="panel-title">Diffie-Hellman 密钥交换</div>
<div class="panel-desc">双方在不安全信道上协商共享密钥</div>
<div class="btn-group">
<button class="btn" onclick="dhGenClient()">客户端密钥</button>
<button class="btn" onclick="dhGenServer()">服务端密钥</button>
<button class="btn" onclick="dhCompute()">计算共享密钥</button>
</div>
<div class="result-container">
<div id="dh-result" class="result" style="display:none"></div>
<button class="copy-btn" onclick="copyResult('dh-result')">复制</button>
</div>
</div>

<!-- 防重放 -->
<div id="panel-replay" class="panel">
<div class="panel-title">防重放攻击滑动窗口</div>
<div class="panel-desc">使用滑动窗口机制检测重放攻击</div>
<div class="form-row">
<label>序列号</label>
<input type="text" id="replay-seq" value="1">
</div>
<div class="btn-group">
<button class="btn" onclick="replayCheck()">检查</button>
<button class="btn" onclick="replayBatch()">批量测试</button>
<button class="btn" onclick="replayAttack()">模拟重放</button>
<button class="btn" onclick="replayReset()">重置</button>
</div>
<div class="result-container">
<div id="replay-result" class="result" style="display:none"></div>
<button class="copy-btn" onclick="copyResult('replay-result')">复制</button>
</div>
</div>

<!-- 密钥轮换 -->
<div id="panel-keymgr" class="panel">
<div class="panel-title">会话密钥轮换</div>
<div class="panel-desc">定期轮换会话密钥增强安全性</div>
<div class="btn-group">
<button class="btn" onclick="kmInit()">初始化</button>
<button class="btn" onclick="kmRotate()">轮换</button>
<button class="btn" onclick="kmStatus()">状态</button>
</div>
<div class="result-container">
<div id="keymgr-result" class="result" style="display:none"></div>
<button class="copy-btn" onclick="copyResult('keymgr-result')">复制</button>
</div>
</div>

<!-- GCM隧道 -->
<div id="panel-tunnel-gcm" class="panel">
<div class="panel-title">VPN隧道 (GCM模式)</div>
<div class="panel-desc">使用AES-GCM加密的VPN隧道</div>
<div class="form-row">
<label>载荷</label>
<textarea id="tunnel-gcm-payload">这是一条通过VPN安全隧道传输的用户数据包</textarea>
</div>
<div class="form-row">
<label>源IP</label>
<input type="text" id="tunnel-gcm-src" value="10.0.0.2">
</div>
<div class="form-row">
<label>目的IP</label>
<input type="text" id="tunnel-gcm-dst" value="10.0.0.1">
</div>
<div class="btn-group">
<button class="btn" onclick="tunnelEnc('GCM')">封装</button>
<button class="btn" onclick="tunnelStats()">统计</button>
</div>
<div class="result-container">
<div id="tunnel-gcm-result" class="result" style="display:none"></div>
<button class="copy-btn" onclick="copyResult('tunnel-gcm-result')">复制</button>
</div>
</div>

<!-- CBC隧道 -->
<div id="panel-tunnel-cbc" class="panel">
<div class="panel-title">VPN隧道 (CBC模式)</div>
<div class="panel-desc">使用AES-CBC加密的VPN隧道</div>
<div class="form-row">
<label>载荷</label>
<textarea id="tunnel-cbc-payload">这是一条通过VPN安全隧道传输的用户数据包</textarea>
</div>
<div class="form-row">
<label>源IP</label>
<input type="text" id="tunnel-cbc-src" value="10.0.0.2">
</div>
<div class="form-row">
<label>目的IP</label>
<input type="text" id="tunnel-cbc-dst" value="10.0.0.1">
</div>
<div class="btn-group">
<button class="btn" onclick="tunnelEnc('CBC')">封装</button>
<button class="btn" onclick="tunnelStats()">统计</button>
</div>
<div class="result-container">
<div id="tunnel-cbc-result" class="result" style="display:none"></div>
<button class="copy-btn" onclick="copyResult('tunnel-cbc-result')">复制</button>
</div>
</div>

<!-- 完整流程 -->
<div id="panel-flow" class="panel">
<div class="panel-title">完整VPN安全通信流程</div>
<div class="panel-desc">一键演示从密钥交换到加密通信的完整流程</div>
<div class="btn-group">
<button class="btn" onclick="runFullFlow()">运行完整演示</button>
</div>
<div class="result-container">
<div id="flow-result" class="result" style="display:none"></div>
<button class="copy-btn" onclick="copyResult('flow-result')">复制</button>
</div>
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

function showToast(msg) {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2000);
}

async function copyResult(id) {
  const el = document.getElementById(id);
  if (el.style.display === 'none') return;
  try {
    await navigator.clipboard.writeText(el.textContent);
    showToast('已复制');
  } catch(e) {
    showToast('复制失败');
  }
}

// ==================== AES-CBC ====================
async function aesCbcEncrypt() {
  try {
    const r = await api('/api/aes/encrypt-cbc', 'POST', {plaintext: document.getElementById('aes-cbc-pt').value});
    showResult('aes-cbc-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('aes-cbc-result', e.message, true); }
}

// ==================== AES-GCM ====================
async function aesGcmEncrypt() {
  try {
    const r = await api('/api/aes/encrypt-gcm', 'POST', {
      plaintext: document.getElementById('aes-gcm-pt').value,
      aad: document.getElementById('aes-gcm-aad').value
    });
    showResult('aes-gcm-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('aes-gcm-result', e.message, true); }
}

// ==================== RSA ====================
async function rsaGenKeys() {
  try {
    const r = await api('/api/rsa/generate-keypair');
    rsaKeys = true;
    showResult('rsa-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('rsa-result', e.message, true); }
}

async function rsaEncrypt() {
  try {
    if (!rsaKeys) await rsaGenKeys();
    const r = await api('/api/rsa/encrypt', 'POST', {plaintext: document.getElementById('rsa-pt').value});
    showResult('rsa-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('rsa-result', e.message, true); }
}

async function rsaDecrypt() {
  try {
    if (!rsaKeys) throw new Error('请先生成密钥对');
    const r = await api('/api/rsa/encrypt', 'POST', {plaintext: document.getElementById('rsa-pt').value});
    const d = await api('/api/rsa/decrypt', 'POST', r.ciphertext);
    showResult('rsa-result', JSON.stringify(d, null, 2));
  } catch(e) { showResult('rsa-result', e.message, true); }
}

// ==================== SHA-256 ====================
async function sha256Hash() {
  try {
    const r = await api('/api/hash/sha256', 'POST', {data: document.getElementById('hash-data').value});
    showResult('hash-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('hash-result', e.message, true); }
}

async function multiHash() {
  try {
    const r = await api('/api/hash/multi', 'POST', {data: document.getElementById('hash-data').value});
    showResult('hash-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('hash-result', e.message, true); }
}

// ==================== HMAC ====================
async function hmacGenerate() {
  try {
    const r = await api('/api/hmac/generate', 'POST', {data: document.getElementById('hmac-data').value});
    showResult('hmac-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('hmac-result', e.message, true); }
}

// ==================== HKDF ====================
async function hkdfDerive() {
  try {
    const r = await api('/api/kdf/hkdf', 'POST', {info: document.getElementById('hkdf-info').value});
    showResult('hkdf-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('hkdf-result', e.message, true); }
}

// ==================== PBKDF2 ====================
async function pbkdf2Derive() {
  try {
    const r = await api('/api/kdf/pbkdf2', 'POST', {
      password: document.getElementById('pbkdf2-pwd').value,
      iterations: parseInt(document.getElementById('pbkdf2-iter').value)
    });
    showResult('pbkdf2-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('pbkdf2-result', e.message, true); }
}

// ==================== 数字签名 ====================
async function dsGenKeys() {
  try {
    await api('/api/signature/generate-keypair');
    dsKeys = true;
    showResult('sign-result', JSON.stringify({status: '密钥对已生成'}, null, 2));
  } catch(e) { showResult('sign-result', e.message, true); }
}

async function dsSign() {
  try {
    if (!dsKeys) await dsGenKeys();
    const r = await api('/api/signature/sign', 'POST', {data: document.getElementById('sign-data').value});
    window._lastSignature = r.signature;
    window._lastSignData = r.data;
    showResult('sign-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('sign-result', e.message, true); }
}

async function dsVerify() {
  try {
    const r = await api('/api/signature/verify', 'POST', {data: window._lastSignData, signature: window._lastSignature});
    showResult('sign-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('sign-result', e.message, true); }
}

async function dsTamperVerify() {
  try {
    const r = await api('/api/signature/verify', 'POST', {data: '篡改后的数据!!!', signature: window._lastSignature});
    showResult('sign-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('sign-result', e.message, true); }
}

// ==================== 证书 ====================
async function certIssue() {
  try {
    const r = await api('/api/certificate/issue', 'POST', {subject: document.getElementById('cert-subject').value});
    lastCertSerial = r.serial_number;
    showResult('cert-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('cert-result', e.message, true); }
}

async function certList() {
  try {
    const r = await api('/api/certificate/list');
    showResult('cert-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('cert-result', e.message, true); }
}

async function certRevokeLast() {
  try {
    if (!lastCertSerial) throw new Error('请先签发证书');
    const r = await api('/api/certificate/revoke', 'POST', {serial_number: lastCertSerial, reason: 'key_compromise'});
    showResult('cert-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('cert-result', e.message, true); }
}

// ==================== CRL ====================
async function certShowCRL() {
  try {
    const r = await api('/api/certificate/crl');
    showResult('crl-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('crl-result', e.message, true); }
}

// ==================== DH ====================
async function dhGenClient() {
  try {
    const r = await api('/api/dh/generate', 'POST', {side: 'client'});
    dhClient = r.public_key;
    showResult('dh-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('dh-result', e.message, true); }
}

async function dhGenServer() {
  try {
    const r = await api('/api/dh/generate', 'POST', {side: 'server'});
    dhServer = r.public_key;
    showResult('dh-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('dh-result', e.message, true); }
}

async function dhCompute() {
  try {
    if (!dhClient || !dhServer) throw new Error('请先生成双方密钥');
    const r = await api('/api/dh/compute-shared', 'POST', {other_public_key: dhServer});
    showResult('dh-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('dh-result', e.message, true); }
}

// ==================== 防重放 ====================
async function replayCheck() {
  try {
    const seq = parseInt(document.getElementById('replay-seq').value);
    const r = await api('/api/anti-replay/check', 'POST', {sequence: seq});
    showResult('replay-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('replay-result', e.message, true); }
}

async function replayBatch() {
  try {
    await api('/api/anti-replay/reset', 'POST');
    const seqs = [3, 1, 7, 2, 5, 4, 6];
    const results = [];
    for (const seq of seqs) {
      const r = await api('/api/anti-replay/check', 'POST', {sequence: seq});
      results.push({sequence: seq, result: r});
    }
    const r2 = await api('/api/anti-replay/check', 'POST', {sequence: 3});
    results.push({sequence: 3, note: '重放测试', result: r2});
    showResult('replay-result', JSON.stringify(results, null, 2));
  } catch(e) { showResult('replay-result', e.message, true); }
}

async function replayAttack() {
  try {
    await api('/api/anti-replay/reset', 'POST');
    await api('/api/anti-replay/check', 'POST', {sequence: 1});
    await api('/api/anti-replay/check', 'POST', {sequence: 2});
    const r = await api('/api/anti-replay/check', 'POST', {sequence: 1});
    showResult('replay-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('replay-result', e.message, true); }
}

async function replayReset() {
  try {
    await api('/api/anti-replay/reset', 'POST');
    showResult('replay-result', JSON.stringify({status: '已重置'}, null, 2));
  } catch(e) { showResult('replay-result', e.message, true); }
}

// ==================== 密钥轮换 ====================
async function kmInit() {
  try {
    const r = await api('/api/key-manager/initialize', 'POST');
    showResult('keymgr-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('keymgr-result', e.message, true); }
}

async function kmRotate() {
  try {
    const r = await api('/api/key-manager/rotate', 'POST');
    showResult('keymgr-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('keymgr-result', e.message, true); }
}

async function kmStatus() {
  try {
    const r = await api('/api/key-manager/status');
    showResult('keymgr-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('keymgr-result', e.message, true); }
}

// ==================== GCM隧道 ====================
async function tunnelEnc(mode) {
  try {
    const payloadId = mode === 'GCM' ? 'tunnel-gcm-payload' : 'tunnel-cbc-payload';
    const srcId = mode === 'GCM' ? 'tunnel-gcm-src' : 'tunnel-cbc-src';
    const dstId = mode === 'GCM' ? 'tunnel-gcm-dst' : 'tunnel-cbc-dst';
    const resultId = mode === 'GCM' ? 'tunnel-gcm-result' : 'tunnel-cbc-result';
    
    const r = await api('/api/tunnel/encapsulate', 'POST', {
      payload: document.getElementById(payloadId).value,
      src_ip: document.getElementById(srcId).value,
      dst_ip: document.getElementById(dstId).value,
      mode: mode
    });
    showResult(resultId, JSON.stringify(r, null, 2));
  } catch(e) { showResult(mode === 'GCM' ? 'tunnel-gcm-result' : 'tunnel-cbc-result', e.message, true); }
}

async function tunnelStats() {
  try {
    const r = await api('/api/tunnel/stats');
    showResult('tunnel-gcm-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('tunnel-gcm-result', e.message, true); }
}

// ==================== 完整流程 ====================
async function runFullFlow() {
  try {
    const r = await api('/api/demo/full-flow');
    showResult('flow-result', JSON.stringify(r, null, 2));
  } catch(e) { showResult('flow-result', e.message, true); }
}
</script>
</body>
</html>"""


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
