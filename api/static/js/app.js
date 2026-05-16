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
