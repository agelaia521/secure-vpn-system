"""
数据完整性校验模块（增强版）
提供数据完整性验证、防篡改检测、防重放攻击（滑动窗口）
"""

import os
import hmac
import hashlib
import json
import time
import threading
from collections import deque


class IntegrityChecker:
    """数据完整性校验器，使用 HMAC-SHA256"""

    def __init__(self, algorithm: str = "sha256"):
        self.algorithm = algorithm

    def generate_tag(self, data, key: bytes = None) -> str:
        if key is None:
            key = os.urandom(32)
        if isinstance(data, str):
            data = data.encode('utf-8')
        tag = hmac.new(key, data, hashlib.sha256).hexdigest()
        return tag

    def generate_tag_bytes(self, data: bytes, key: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()

    def verify_tag(self, data, tag: str, key: bytes = None) -> bool:
        if key is None:
            if isinstance(data, str):
                data = data.encode('utf-8')
            expected = hashlib.sha256(data).hexdigest()
            return hmac.compare_digest(expected, tag)
        if isinstance(data, str):
            data = data.encode('utf-8')
        expected = hmac.new(key, data, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, tag)

    def verify_tag_bytes(self, data: bytes, tag: bytes, key: bytes) -> bool:
        expected = hmac.new(key, data, hashlib.sha256).digest()
        return hmac.compare_digest(expected, tag)

    def compute_checksum(self, data: bytes) -> str:
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        return f"MD5:{md5}|SHA1:{sha1[:16]}|SHA256:{sha256[:16]}"

    def verify_packet_integrity(self, packet: dict, key: bytes) -> dict:
        result = {"valid": False, "details": {}}
        data = packet.get("data")
        stored_tag = packet.get("integrity_tag")
        if data is None or stored_tag is None:
            result["details"]["error"] = "数据包缺少data或integrity_tag字段"
            return result
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data
        expected_tag = hmac.new(key, data_bytes, hashlib.sha256).hexdigest()
        hmac_valid = hmac.compare_digest(expected_tag, stored_tag)
        result["details"]["hmac_verify"] = hmac_valid
        if "hash" in packet:
            computed_hash = hashlib.sha256(data_bytes).hexdigest()
            hash_valid = hmac.compare_digest(computed_hash, packet["hash"])
            result["details"]["hash_verify"] = hash_valid
        else:
            result["details"]["hash_verify"] = None
        if "sequence" in packet:
            result["details"]["sequence"] = packet["sequence"]
        result["valid"] = hmac_valid
        return result


class AntiReplayWindow:
    """
    防重放攻击滑动窗口
    基于序列号的滑动窗口机制，检测并拒绝重复或过期的数据包
    
    原理：
    - 维护一个滑动窗口 [window_right - WINDOW_SIZE + 1, window_right]
    - 窗口内已收到的序列号记录在位图中
    - 序列号 > window_right: 接受，滑动窗口
    - 序列号在窗口内且未出现过: 接受
    - 序列号在窗口内且已出现过: 拒绝（重放攻击）
    - 序列号 < window_left: 拒绝（过期包）
    """

    WINDOW_SIZE = 64          # 滑动窗口大小
    CLOCK_DRIFT_TOLERANCE = 300  # 时钟漂移容忍度(秒)

    def __init__(self, window_size: int = 64):
        self.window_size = window_size
        self.window_right = 0       # 窗口右边界（最大已接收序列号）
        self.bitmap = set()         # 窗口内已接收的序列号集合
        self.lock = threading.Lock()
        self.total_received = 0
        self.total_rejected = 0
        self.total_replay_detected = 0

    def check_and_update(self, sequence: int, timestamp: float = None) -> dict:
        """
        检查序列号是否合法并更新窗口
        :param sequence: 数据包序列号
        :param timestamp: 数据包时间戳(可选，用于时间窗口检查)
        :return: {"accepted": bool, "reason": str}
        """
        with self.lock:
            # 时间戳检查
            if timestamp is not None:
                now = time.time()
                if abs(now - timestamp) > self.CLOCK_DRIFT_TOLERANCE:
                    self.total_rejected += 1
                    return {
                        "accepted": False,
                        "reason": f"时间戳超出容忍范围（差值: {abs(now - timestamp):.1f}秒）"
                    }

            window_left = self.window_right - self.window_size + 1

            # 情况1: 序列号远大于窗口右边界 → 滑动窗口
            if sequence > self.window_right:
                # 移除窗口外的序列号
                new_left = sequence - self.window_size + 1
                self.bitmap = {s for s in self.bitmap if s >= new_left}
                self.window_right = sequence
                self.bitmap.add(sequence)
                self.total_received += 1
                return {"accepted": True, "reason": "新序列号，窗口已滑动"}

            # 情况2: 序列号在窗口左侧之外 → 拒绝（过期）
            if sequence < window_left:
                self.total_rejected += 1
                return {
                    "accepted": False,
                    "reason": f"序列号过期（seq={sequence}, 窗口=[{window_left}, {self.window_right}]）"
                }

            # 情况3: 序列号在窗口内
            if sequence in self.bitmap:
                # 已出现过 → 重放攻击
                self.total_replay_detected += 1
                self.total_rejected += 1
                return {
                    "accepted": False,
                    "reason": f"检测到重放攻击（重复序列号: {sequence}）"
                }
            else:
                # 未出现过 → 接受
                self.bitmap.add(sequence)
                self.total_received += 1
                return {"accepted": True, "reason": "序列号在窗口内且首次出现"}

    def reset(self):
        """重置滑动窗口"""
        with self.lock:
            self.window_right = 0
            self.bitmap.clear()
            self.total_received = 0
            self.total_rejected = 0
            self.total_replay_detected = 0

    def get_stats(self) -> dict:
        """获取窗口统计信息"""
        with self.lock:
            window_left = self.window_right - self.window_size + 1
            return {
                "window_range": f"[{window_left}, {self.window_right}]",
                "window_size": self.window_size,
                "received_in_window": len(self.bitmap),
                "total_received": self.total_received,
                "total_rejected": self.total_rejected,
                "replay_detected": self.total_replay_detected,
                "rejection_rate": f"{self.total_rejected / max(1, self.total_received + self.total_rejected) * 100:.2f}%"
            }


class SessionKeyManager:
    """
    会话密钥管理器
    支持密钥轮换（Key Rotation）和密钥生命周期管理
    """

    def __init__(self, key_lifetime: int = 3600):
        """
        :param key_lifetime: 密钥生命周期(秒)，默认1小时
        """
        self.key_lifetime = key_lifetime
        self.current_key = None
        self.previous_key = None
        self.key_created_at = 0
        self.key_version = 0
        self.rotation_count = 0
        self.lock = threading.Lock()

    def initialize(self, initial_key: bytes):
        """初始化密钥"""
        with self.lock:
            self.current_key = initial_key
            self.key_created_at = time.time()
            self.key_version = 1

    def rotate(self, new_key: bytes = None):
        """
        密钥轮换
        将当前密钥降级为前一个密钥，使用新密钥
        """
        with self.lock:
            if new_key is None:
                new_key = os.urandom(32)

            self.previous_key = self.current_key
            self.current_key = new_key
            self.key_created_at = time.time()
            self.key_version += 1
            self.rotation_count += 1

    def should_rotate(self) -> bool:
        """检查是否需要轮换密钥"""
        with self.lock:
            if self.current_key is None:
                return False
            return (time.time() - self.key_created_at) >= self.key_lifetime

    def auto_rotate_if_needed(self):
        """自动轮换（如果需要）"""
        if self.should_rotate():
            self.rotate()
            return True
        return False

    def get_current_key(self) -> bytes:
        """获取当前密钥"""
        return self.current_key

    def get_key_by_version(self, version: int) -> bytes:
        """根据版本获取密钥（用于解密旧数据）"""
        with self.lock:
            if version == self.key_version:
                return self.current_key
            elif version == self.key_version - 1:
                return self.previous_key
            else:
                return None

    def get_status(self) -> dict:
        """获取密钥状态"""
        with self.lock:
            age = time.time() - self.key_created_at if self.current_key else 0
            remaining = max(0, self.key_lifetime - age)
            return {
                "key_version": self.key_version,
                "key_age_seconds": int(age),
                "key_remaining_seconds": int(remaining),
                "needs_rotation": age >= self.key_lifetime,
                "rotation_count": self.rotation_count,
                "has_previous_key": self.previous_key is not None
            }
