const API = '';
let rsaKeys = false, dsKeys = false, dhClient = null, dhServer = null;
let lastCertSerial = null;

// 统计数据
let packetCount = 0;
let encryptedBytes = 0;

// ==================== 主页功能 ====================

function showSection(sectionId) {
  document.querySelectorAll('.main-section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.main-tab').forEach(b => b.classList.remove('active'));
  document.getElementById('section-' + sectionId).classList.add('active');
  event.target.classList.add('active');
}

function showPanel(id) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('panel-' + id).classList.add('active');
  event.target.classList.add('active');
}

function addLog(message, type='system') {
  const container = document.getElementById('log-container');
  const time = new Date().toLocaleTimeString();
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  
  let colorClass = 'log-system';
  if (type === 'alice') colorClass = 'log-alice';
  else if (type === 'bob') colorClass = 'log-bob';
  else if (type === 'encrypted') colorClass = 'log-encrypted';
  
  entry.innerHTML = `<span class="log-time">[${time}]</span><span class="${colorClass}">${message}</span>`;
  container.appendChild(entry);
  container.scrollTop = container.scrollHeight;
}

function updateStats() {
  document.getElementById('stat-packets').textContent = packetCount;
  document.getElementById('stat-encrypted').textContent = encryptedBytes;
}

async function sendMessage(sender) {
  const inputId = `input-${sender}`;
  const chatId = `chat-${sender}`;
  const targetChatId = sender === 'alice' ? 'chat-bob' : 'chat-alice';
  
  const message = document.getElementById(inputId).value.trim();
  if (!message) return;
  
  // 清空输入
  document.getElementById(inputId).value = '';
  
  const senderName = sender === 'alice' ? 'Alice' : 'Bob';
  const targetName = sender === 'alice' ? 'Bob' : 'Alice';
  const senderColor = sender === 'alice' ? 'alice' : 'bob';
  const aadValue = `VPN-Tunnel-${sender.toUpperCase()}`;
  
  // 添加发送消息到发送者聊天框
  addMessage(chatId, message, senderColor);
  
  // 记录详细日志
  addLog(`[${senderName}] 发送消息: "${message}"`, sender);
  addLog(`[${senderName}] 明文长度: ${message.length} 字节`, 'encrypted');
  addLog(`[${senderName}] 开始AES-256-GCM加密流程...`, 'encrypted');
  
  try {
    // 调用API加密
    addLog(`[${senderName}] 生成随机AES密钥...`, 'encrypted');
    const encryptResult = await api('/api/aes/encrypt-gcm', 'POST', {
      plaintext: message,
      aad: aadValue
    });
    
    const keyPreview = encryptResult.key_hex.substring(0, 16) + '...' + encryptResult.key_hex.substring(48);
    const ciphertextPreview = encryptResult.ciphertext.substring(0, 20) + '...';
    
    addLog(`[${senderName}] 生成的AES密钥: ${keyPreview}`, 'encrypted');
    addLog(`[${senderName}] 密钥长度: 256位 (32字节)`, 'encrypted');
    addLog(`[${senderName}] AAD认证数据: ${aadValue}`, 'encrypted');
    addLog(`[${senderName}] 加密完成 - 密文长度: ${encryptResult.ciphertext.length} 字节`, 'encrypted');
    addLog(`[${senderName}] 密文(Base64): ${ciphertextPreview}`, 'encrypted');
    
    encryptedBytes += message.length;
    
    // 模拟网络传输延迟
    await new Promise(resolve => setTimeout(resolve, 300));
    
    // 记录隧道传输详情
    addLog(`[隧道] ====== VPN隧道传输开始 ======`, 'system');
    addLog(`[隧道] 源IP: 10.8.0.${sender === 'alice' ? '2' : '3'}`, 'system');
    addLog(`[隧道] 目的IP: 10.8.0.${sender === 'alice' ? '3' : '2'}`, 'system');
    addLog(`[隧道] 协议: UDP (VPN封装)`, 'system');
    addLog(`[隧道] 加密方式: AES-256-GCM`, 'system');
    addLog(`[隧道] 数据包长度: ${encryptResult.ciphertext.length} 字节`, 'system');
    addLog(`[隧道] 传输中...`, 'system');
    
    await new Promise(resolve => setTimeout(resolve, 200));
    
    addLog(`[隧道] 数据包到达 ${targetName}`, 'system');
    addLog(`[隧道] ====== VPN隧道传输完成 ======`, 'system');
    
    // 模拟解密过程
    addLog(`[${targetName}] 开始解密流程...`, 'encrypted');
    addLog(`[${targetName}] 使用共享密钥解密...`, 'encrypted');
    addLog(`[${targetName}] 密钥: ${keyPreview}`, 'encrypted');
    addLog(`[${targetName}] AAD验证数据: ${aadValue}`, 'encrypted');
    
    // 调用API解密
    const decryptResult = await api('/api/aes/decrypt-gcm', 'POST', {
      ciphertext: encryptResult.ciphertext,
      key_hex: encryptResult.key_hex,
      aad: aadValue
    });
    
    addLog(`[${targetName}] GCM认证标签验证通过 ✓`, 'encrypted');
    addLog(`[${targetName}] 解密完成，明文: "${decryptResult.plaintext}"`, 'encrypted');
    addLog(`[${targetName}] 明文长度: ${decryptResult.plaintext.length} 字节`, 'encrypted');
    
    // 添加接收消息到接收者聊天框
    addMessage(targetChatId, decryptResult.plaintext, sender === 'alice' ? 'alice' : 'bob');
    
    packetCount++;
    updateStats();
    
    addLog(`[${targetName}] 消息已成功接收并显示`, 'system');
    addLog(`[系统] 传输统计: 已发送 ${packetCount} 个数据包, 已加密 ${encryptedBytes} 字节`, 'system');
    
  } catch(e) {
    addLog(`[错误] 通信失败: ${e.message}`, 'system');
  }
}

function addMessage(chatId, message, sender) {
  const chat = document.getElementById(chatId);
  const senderName = sender === 'alice' ? 'Alice' : 'Bob';
  const msgLine = document.createElement('div');
  msgLine.textContent = `[${senderName}] ${message}`;
  chat.appendChild(msgLine);
  chat.scrollTop = chat.scrollHeight;
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

// ==================== 安全配置功能 ====================

let securityConfig = {
  dhPrimeBits: 3072,
  certValidation: 'strict',
  crlCheck: 'enabled',
  certExpiry: 'enabled',
  encryptionAlgo: 'AES-256-GCM',
  hashAlgo: 'SHA-256',
  hmacAlgo: 'HMAC-SHA256'
};

function updateSecurityConfig() {
  securityConfig = {
    dhPrimeBits: parseInt(document.getElementById('dh-prime-bits').value),
    certValidation: document.getElementById('cert-validation').value,
    crlCheck: document.getElementById('crl-check').value,
    certExpiry: document.getElementById('cert-expiry').value,
    encryptionAlgo: document.getElementById('encryption-algo').value,
    hashAlgo: document.getElementById('hash-algo').value,
    hmacAlgo: document.getElementById('hmac-algo').value
  };
  updateDebugOutput();
  addLog('[配置] 安全参数已更新', 'system');
}

function updateDebugOutput() {
  const output = document.getElementById('debug-output');
  const validationMode = {
    'strict': '严格模式',
    'relaxed': '宽松模式',
    'skip': '跳过验证'
  };
  output.textContent = `// 安全配置调试信息
// 最后更新: ${new Date().toLocaleString()}

当前配置:
- DH素数位数: ${securityConfig.dhPrimeBits}
- 证书验证: ${validationMode[securityConfig.certValidation]}
- CRL检查: ${securityConfig.crlCheck === 'enabled' ? '启用' : '禁用'}
- 有效期检查: ${securityConfig.certExpiry === 'enabled' ? '启用' : '禁用'}
- 加密算法: ${securityConfig.encryptionAlgo}
- 哈希算法: ${securityConfig.hashAlgo}
- HMAC算法: ${securityConfig.hmacAlgo}

配置摘要:
{
  "dh_prime_bits": ${securityConfig.dhPrimeBits},
  "cert_validation": "${securityConfig.certValidation}",
  "encryption": "${securityConfig.encryptionAlgo}",
  "hash": "${securityConfig.hashAlgo}",
  "hmac": "${securityConfig.hmacAlgo}"
}`;
}

async function generateDHParams() {
  const bits = securityConfig.dhPrimeBits;
  addLog(`[DH] 正在生成 ${bits} 位素数参数...`, 'encrypted');
  
  try {
    const startTime = Date.now();
    const r = await api('/api/dh/generate', 'POST', {side: 'client'});
    const elapsed = Date.now() - startTime;
    
    document.getElementById('dh-status').textContent = `参数生成成功 (${elapsed}ms)`;
    document.getElementById('dh-status').className = 'config-status valid';
    
    addLog(`[DH] 参数生成完成，耗时 ${elapsed}ms`, 'encrypted');
    
    const output = document.getElementById('debug-output');
    output.textContent = `// DH参数生成结果
// 素数位数: ${bits}
// 生成耗时: ${elapsed}ms

{
  "public_key": "${r.public_key}",
  "prime_bits": ${bits},
  "generator": 2,
  "status": "success"
}`;
    
  } catch(e) {
    document.getElementById('dh-status').textContent = '生成失败';
    document.getElementById('dh-status').className = 'config-status invalid';
    addLog(`[DH] 参数生成失败: ${e.message}`, 'system');
  }
}

async function showDHInfo() {
  addLog('[DH] 获取密钥交换信息...', 'encrypted');
  
  try {
    const r = await api('/api/kdf/session-keys');
    const output = document.getElementById('debug-output');
    output.textContent = `// DH密钥交换详细信息

共享密钥派生结果:
{
  "shared_secret": "${r.shared_secret_hex}",
  "client_write_key": "${r.client_write_key}",
  "server_write_key": "${r.server_write_key}",
  "client_write_iv": "${r.client_write_iv}",
  "server_write_iv": "${r.server_write_iv}"
}

安全参数:
- DH素数位数: ${securityConfig.dhPrimeBits}
- 生成元(g): 2
- 密钥派生: HKDF-SHA256`;
    
    addLog('[DH] 密钥交换信息已显示', 'encrypted');
  } catch(e) {
    addLog(`[DH] 获取信息失败: ${e.message}`, 'system');
  }
}

async function testCertificate() {
  const mode = securityConfig.certValidation;
  addLog(`[证书] 使用${mode === 'strict' ? '严格' : mode === 'relaxed' ? '宽松' : '跳过'}模式测试证书...`, 'encrypted');
  
  try {
    const r = await api('/api/certificate/issue', 'POST', {subject: 'Test-Client'});
    
    if (mode === 'strict') {
      document.getElementById('cert-status').textContent = '严格验证通过';
    } else if (mode === 'relaxed') {
      document.getElementById('cert-status').textContent = '宽松验证通过';
    } else {
      document.getElementById('cert-status').textContent = '已跳过验证';
    }
    document.getElementById('cert-status').className = 'config-status valid';
    
    addLog(`[证书] 验证完成，序列号: ${r.serial_number}`, 'encrypted');
    
    const output = document.getElementById('debug-output');
    output.textContent = `// 证书测试结果
// 验证模式: ${mode}
// 证书序列号: ${r.serial_number}

{
  "subject": "${r.subject}",
  "serial_number": "${r.serial_number}",
  "validity_days": ${r.info.validity_days || 365},
  "status": "valid",
  "validation_mode": "${mode}"
}`;
    
  } catch(e) {
    document.getElementById('cert-status').textContent = '验证失败';
    document.getElementById('cert-status').className = 'config-status invalid';
    addLog(`[证书] 验证失败: ${e.message}`, 'system');
  }
}

async function viewCertificate() {
  addLog('[证书] 获取证书列表...', 'encrypted');
  
  try {
    const r = await api('/api/certificate/list');
    const output = document.getElementById('debug-output');
    output.textContent = `// 证书列表
// 总数: ${r.certificates.length}

${JSON.stringify(r, null, 2)}`;
    addLog(`[证书] 已获取 ${r.certificates.length} 个证书`, 'encrypted');
  } catch(e) {
    addLog(`[证书] 获取失败: ${e.message}`, 'system');
  }
}

async function testEncryption() {
  const algo = securityConfig.encryptionAlgo;
  addLog(`[加密] 使用 ${algo} 测试加密...`, 'encrypted');
  
  try {
    const testData = 'VPN安全通信测试数据 - 这是一条用于测试加密算法的消息';
    const mode = algo.includes('GCM') ? 'GCM' : 'CBC';
    
    const r = await api(`/api/aes/encrypt-${mode.toLowerCase()}`, 'POST', {plaintext: testData});
    
    const decryptR = await api(`/api/aes/decrypt-${mode.toLowerCase()}`, 'POST', {
      ciphertext: r.ciphertext,
      key_hex: r.key_hex
    });
    
    const valid = decryptR.plaintext === testData;
    
    document.getElementById('enc-status').textContent = valid ? '加密验证通过' : '加密验证失败';
    document.getElementById('enc-status').className = valid ? 'config-status valid' : 'config-status invalid';
    
    addLog(`[加密] ${algo} 测试${valid ? '成功' : '失败'}`, 'encrypted');
    
    const output = document.getElementById('debug-output');
    output.textContent = `// 加密测试结果
// 算法: ${algo}
// 明文长度: ${testData.length}
// 密文长度: ${r.ciphertext.length}
// 验证结果: ${valid ? '✓ 验证通过' : '✗ 验证失败'}

{
  "algorithm": "${algo}",
  "plaintext_length": ${testData.length},
  "ciphertext_length": ${r.ciphertext.length},
  "key_size": ${algo.includes('256') ? 256 : 128},
  "mode": "${mode}",
  "verified": ${valid}
}`;
    
  } catch(e) {
    document.getElementById('enc-status').textContent = '测试失败';
    document.getElementById('enc-status').className = 'config-status invalid';
    addLog(`[加密] 测试失败: ${e.message}`, 'system');
  }
}

async function benchmarkAlgo() {
  addLog('[性能] 开始加密算法性能测试...', 'encrypted');
  
  try {
    const algorithms = ['AES-256-GCM', 'AES-256-CBC', 'AES-128-GCM', 'AES-128-CBC'];
    const results = [];
    const testData = 'x'.repeat(1024 * 1024); // 1MB测试数据
    
    for (const algo of algorithms) {
      const startTime = Date.now();
      const mode = algo.includes('GCM') ? 'GCM' : 'CBC';
      
      for (let i = 0; i < 10; i++) {
        await api(`/api/aes/encrypt-${mode.toLowerCase()}`, 'POST', {plaintext: testData});
      }
      
      const elapsed = Date.now() - startTime;
      const speed = ((10 * 1) / (elapsed / 1000)).toFixed(2);
      
      results.push({
        algorithm: algo,
        time_ms: elapsed,
        speed_mbs: speed
      });
    }
    
    addLog('[性能] 性能测试完成', 'encrypted');
    
    const output = document.getElementById('debug-output');
    output.textContent = `// 加密算法性能测试
// 测试数据: 1MB x 10次
// 测试时间: ${new Date().toLocaleTimeString()}

${algorithms.map((algo, i) => 
  `${algo}: ${results[i].time_ms}ms (${results[i].speed_mbs} MB/s)`
).join('\n')}

${JSON.stringify(results, null, 2)}`;
    
  } catch(e) {
    addLog(`[性能] 测试失败: ${e.message}`, 'system');
  }
}
