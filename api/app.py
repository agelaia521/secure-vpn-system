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
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
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

app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")), name="static")

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

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
