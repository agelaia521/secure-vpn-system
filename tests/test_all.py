"""单元测试"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.aes_cipher import AESCipher, KeyDerivation
from crypto.rsa_cipher import RSACipher
from crypto.hash_mac import HashMAC
from security.digital_signature import DigitalSignature
from security.certificate import CertificateAuthority
from security.key_exchange import DHKeyExchange
from security.integrity import IntegrityChecker, AntiReplayWindow, SessionKeyManager
from tunnel.tunnel_protocol import TunnelProtocol


class TestAESCipher(unittest.TestCase):
    def setUp(self):
        self.aes = AESCipher()
        self.key = self.aes.generate_key()

    def test_cbc_encrypt_decrypt(self):
        pt = "测试AES-CBC加密解密"
        ct = self.aes.encrypt_cbc(pt, self.key)
        self.assertEqual(self.aes.decrypt_cbc(ct, self.key), pt)

    def test_gcm_encrypt_decrypt(self):
        pt = "测试AES-GCM加密解密"
        ct = self.aes.encrypt_gcm(pt, self.key)
        self.assertEqual(self.aes.decrypt_gcm(ct, self.key), pt)

    def test_gcm_with_aad(self):
        pt = "AAD测试"
        aad = b"test-context"
        ct = self.aes.encrypt_gcm(pt, self.key, aad=aad)
        self.assertEqual(self.aes.decrypt_gcm(ct, self.key, aad=aad), pt)

    def test_gcm_tamper_detection(self):
        pt = "篡改检测"
        ct = self.aes.encrypt_gcm(pt, self.key)
        tampered = ct[:-4] + "XXXX"
        with self.assertRaises(Exception):
            self.aes.decrypt_gcm(tampered, self.key)

    def test_gcm_aad_mismatch(self):
        ct = self.aes.encrypt_gcm("data", self.key, aad=b"correct")
        with self.assertRaises(Exception):
            self.aes.decrypt_gcm(ct, self.key, aad=b"wrong")

    def test_cbc_different_iv(self):
        pt = "相同明文不同密文"
        ct1 = self.aes.encrypt_cbc(pt, self.key)
        ct2 = self.aes.encrypt_cbc(pt, self.key)
        self.assertNotEqual(ct1, ct2)

    def test_bytes_encrypt_decrypt(self):
        data = b"binary data test"
        ct = self.aes.encrypt_bytes(data, self.key)
        self.assertEqual(self.aes.decrypt_bytes(ct, self.key), data)


class TestRSA(unittest.TestCase):
    def setUp(self):
        self.rsa = RSACipher()
        self.kp = self.rsa.generate_key_pair()

    def test_encrypt_decrypt(self):
        msg = "RSA加密测试消息"
        ct = self.rsa.encrypt(msg, self.kp["public_key"])
        self.assertEqual(self.rsa.decrypt(ct, self.kp["private_key"]), msg)

    def test_pem_export_import(self):
        pub_pem = self.rsa.export_public_key_pem(self.kp["public_key"])
        priv_pem = self.rsa.export_private_key_pem(self.kp["private_key"])
        pub = self.rsa.import_public_key_pem(pub_pem)
        priv = self.rsa.import_private_key_pem(priv_pem)
        msg = "PEM导入导出测试"
        self.assertEqual(self.rsa.decrypt(self.rsa.encrypt(msg, pub), priv), msg)


class TestHashMAC(unittest.TestCase):
    def setUp(self):
        self.hm = HashMAC()

    def test_sha256(self):
        h = self.hm.sha256_hash("test")
        self.assertEqual(len(h), 64)

    def test_hmac_verify(self):
        key = self.hm.generate_hmac_key()
        tag = self.hm.hmac_generate("data", key)
        self.assertTrue(self.hm.hmac_verify("data", tag, key))
        self.assertFalse(self.hm.hmac_verify("wrong", tag, key))

    def test_multi_hash(self):
        result = self.hm.multi_hash("test")
        self.assertIn("SHA-256", result)
        self.assertIn("SHA-512", result)


class TestKeyDerivation(unittest.TestCase):
    def test_hkdf(self):
        master = os.urandom(32)
        k1 = KeyDerivation.hkdf_derive(master, b"key1")
        k2 = KeyDerivation.hkdf_derive(master, b"key2")
        self.assertEqual(len(k1), 32)
        self.assertNotEqual(k1, k2)

    def test_hkdf_multiple(self):
        master = os.urandom(32)
        keys = KeyDerivation.hkdf_derive_multiple(master)
        self.assertEqual(len(keys), 3)

    def test_pbkdf2(self):
        key, salt = KeyDerivation.pbkdf2_derive("password", iterations=1000)
        self.assertEqual(len(key), 32)
        key2, _ = KeyDerivation.pbkdf2_derive("password", salt=salt, iterations=1000)
        self.assertEqual(key, key2)

    def test_session_keys(self):
        shared = os.urandom(32)
        sk = KeyDerivation.derive_session_keys(shared)
        self.assertIn("client_write_key", sk)
        self.assertIn("server_write_key", sk)
        self.assertEqual(len(sk["client_write_key"]), 32)


class TestDigitalSignature(unittest.TestCase):
    def setUp(self):
        self.ds = DigitalSignature()
        self.kp = self.ds.generate_key_pair()

    def test_sign_verify(self):
        data = "签名测试"
        sig = self.ds.sign(data, self.kp["private_key"])
        self.assertTrue(self.ds.verify(data, sig, self.kp["public_key"]))

    def test_tamper_detection(self):
        sig = self.ds.sign("original", self.kp["private_key"])
        self.assertFalse(self.ds.verify("tampered", sig, self.kp["public_key"]))


class TestCertificate(unittest.TestCase):
    def setUp(self):
        self.ca = CertificateAuthority()

    def test_issue_verify(self):
        cert = self.ca.issue_certificate("Test-Subject")
        result = self.ca.verify_certificate(cert)
        self.assertTrue(result["valid"])

    def test_revoke(self):
        cert = self.ca.issue_certificate("Revoke-Test")
        self.ca.revoke_certificate(cert["serial_number"], "key_compromise")
        result = self.ca.verify_certificate(cert)
        self.assertFalse(result["valid"])
        self.assertIn("吊销", result["details"]["revocation"])

    def test_forged_cert(self):
        cert = self.ca.issue_certificate("Original")
        import copy
        fake = copy.deepcopy(cert)
        fake["subject"] = "Fake"
        result = self.ca.verify_certificate(fake)
        self.assertFalse(result["valid"])

    def test_crl(self):
        cert = self.ca.issue_certificate("CRL-Test")
        self.ca.revoke_certificate(cert["serial_number"])
        self.assertTrue(self.ca.is_revoked(cert["serial_number"]))
        self.assertEqual(self.ca.crl.get_revoked_count(), 1)


class TestDHKeyExchange(unittest.TestCase):
    def test_shared_secret(self):
        dh_a = DHKeyExchange()
        dh_b = DHKeyExchange()
        pub_a, _ = dh_a.generate_key_pair()
        pub_b, _ = dh_b.generate_key_pair()
        shared_a = dh_a.compute_shared_secret(pub_b)
        shared_b = dh_b.compute_shared_secret(pub_a)
        self.assertEqual(shared_a, shared_b)
        self.assertEqual(len(shared_a), 32)


class TestAntiReplay(unittest.TestCase):
    def setUp(self):
        self.arw = AntiReplayWindow(window_size=8)

    def test_accept_new(self):
        r = self.arw.check_and_update(1)
        self.assertTrue(r["accepted"])

    def test_reject_replay(self):
        self.arw.check_and_update(1)
        r = self.arw.check_and_update(1)
        self.assertFalse(r["accepted"])
        self.assertIn("重放", r["reason"])

    def test_reject_old(self):
        for i in range(1, 10):
            self.arw.check_and_update(i)
        r = self.arw.check_and_update(0)
        self.assertFalse(r["accepted"])

    def test_out_of_order(self):
        self.arw.check_and_update(5)
        r = self.arw.check_and_update(3)
        self.assertTrue(r["accepted"])


class TestSessionKeyManager(unittest.TestCase):
    def test_rotation(self):
        skm = SessionKeyManager()
        skm.initialize(os.urandom(32))
        self.assertEqual(skm.get_status()["key_version"], 1)
        skm.rotate()
        self.assertEqual(skm.get_status()["key_version"], 2)
        self.assertEqual(skm.get_status()["rotation_count"], 1)

    def test_get_by_version(self):
        skm = SessionKeyManager()
        old_key = os.urandom(32)
        skm.initialize(old_key)
        new_key = os.urandom(32)
        skm.rotate(new_key)
        self.assertEqual(skm.get_key_by_version(2), new_key)
        self.assertEqual(skm.get_key_by_version(1), old_key)


class TestTunnel(unittest.TestCase):
    def setUp(self):
        self.shared = os.urandom(32)

    def test_gcm_tunnel(self):
        tunnel = TunnelProtocol(encrypt_mode="GCM")
        pt = "GCM隧道测试"
        pkt = tunnel.encapsulate(pt, "10.0.0.1", "10.0.0.2", "TCP", self.shared)
        self.assertEqual(tunnel.decapsulate(pkt, self.shared), pt)

    def test_cbc_tunnel(self):
        tunnel = TunnelProtocol(encrypt_mode="CBC")
        pt = "CBC隧道测试"
        pkt = tunnel.encapsulate(pt, "10.0.0.1", "10.0.0.2", "TCP", self.shared)
        self.assertEqual(tunnel.decapsulate(pkt, self.shared), pt)

    def test_replay_rejection(self):
        tunnel = TunnelProtocol(encrypt_mode="GCM")
        pkt = tunnel.encapsulate("data", "10.0.0.1", "10.0.0.2", "TCP", self.shared)
        tunnel.decapsulate(pkt, self.shared)
        with self.assertRaises(ValueError):
            tunnel.decapsulate(pkt, self.shared)

    def test_tamper_rejection(self):
        tunnel = TunnelProtocol(encrypt_mode="GCM")
        pkt = tunnel.encapsulate("data", "10.0.0.1", "10.0.0.2", "TCP", self.shared)
        pkt["hmac_tag"] = "0" * 64
        with self.assertRaises(ValueError):
            tunnel.decapsulate(pkt, self.shared)

    def test_compression(self):
        tunnel = TunnelProtocol(encrypt_mode="GCM", enable_compression=True)
        long_data = "A" * 500
        pkt = tunnel.encapsulate(long_data, "10.0.0.1", "10.0.0.2", "TCP", self.shared)
        self.assertEqual(tunnel.decapsulate(pkt, self.shared), long_data)

    def test_stats(self):
        tunnel = TunnelProtocol(encrypt_mode="GCM")
        tunnel.encapsulate("data", "10.0.0.1", "10.0.0.2", "TCP", self.shared)
        stats = tunnel.get_stats()
        self.assertEqual(stats["packets_sent"], 1)


if __name__ == "__main__":
    unittest.main()
