"""Review-rule tests: replay window adjudication, sequence recovery,
KeyUpdate ratchet discipline, and violation offsets."""
import hashlib
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from server.crypto import derive_record_keys, ratchet_secret, record_nonce
from server.dtls import (
    Receiver,
    ReplayWindow,
    Violation,
    parse_unified_header,
    reconstruct_seq,
    run_audit,
)
from server.encode import key_update_record, seal_record

SECRET3 = bytes(range(32))  # arbitrary 32-byte initial traffic secret


def appdata(secret, epoch, seq, payload=b"x", **kw):
    return seal_record(secret, epoch, seq, payload, 23, **kw)


class WindowRuleTests(unittest.TestCase):
    def test_first_record_is_new(self):
        w = ReplayWindow()
        self.assertEqual(w.classify(0), "new")
        w.advance(0)
        self.assertEqual((w.highest, w.bitmap), (0, 1))

    def test_exact_replay_is_duplicate(self):
        w = ReplayWindow()
        w.advance(5)
        self.assertEqual(w.classify(5), "duplicate")

    def test_unseen_inside_window_is_new(self):
        w = ReplayWindow()
        w.advance(5)
        self.assertEqual(w.classify(4), "new")
        w.advance(4)
        self.assertEqual(w.classify(4), "duplicate")

    def test_boundary_offset_63_new_offset_64_too_old(self):
        w = ReplayWindow()
        w.advance(64)
        self.assertEqual(w.classify(1), "new")       # offset 63, inside window
        self.assertEqual(w.classify(0), "too_old")   # offset 64, expired
        w.advance(1)
        self.assertEqual(w.classify(1), "duplicate")

    def test_large_jump_resets_bitmap(self):
        w = ReplayWindow()
        w.advance(0)
        w.advance(3)
        w.advance(200)  # shift >= 64
        self.assertEqual((w.highest, w.bitmap), (200, 1))
        self.assertEqual(w.classify(199), "new")
        self.assertEqual(w.classify(136), "too_old")

    def test_duplicate_does_not_change_window(self):
        w = ReplayWindow()
        w.advance(7)
        before = (w.highest, w.bitmap)
        self.assertEqual(w.classify(7), "duplicate")
        self.assertEqual((w.highest, w.bitmap), before)


class SequenceRecoveryTests(unittest.TestCase):
    def test_8bit_wraparound(self):
        self.assertEqual(reconstruct_seq(255, 0, 8), 256)

    def test_8bit_late_record(self):
        self.assertEqual(reconstruct_seq(260, 2, 8), 258)

    def test_16bit_wraparound(self):
        self.assertEqual(reconstruct_seq(65535, 0, 16), 65536)

    def test_first_record(self):
        self.assertEqual(reconstruct_seq(-1, 5, 8), 5)
        self.assertEqual(reconstruct_seq(-1, 0, 16), 0)

    def test_reconstructed_seq_matches_header(self):
        rx = Receiver(3, SECRET3)
        rx.process_record(appdata(SECRET3, 3, 300, b"a"))
        row = rx.process_record(appdata(SECRET3, 3, 301, b"b"))
        self.assertEqual(row["seq"], 301)


class HeaderRuleTests(unittest.TestCase):
    def test_fixed_bits_enforced(self):
        with self.assertRaises(Violation) as ctx:
            parse_unified_header(b"\x40\x00")
        self.assertEqual((ctx.exception.kind, ctx.exception.offset), ("state", 0))

    def test_cid_bit_rejected(self):
        with self.assertRaises(Violation) as ctx:
            parse_unified_header(b"\x30\x00")  # 001 1 .... -> CID present
        self.assertEqual((ctx.exception.kind, ctx.exception.offset), ("state", 0))

    def test_truncated_sequence_number(self):
        with self.assertRaises(Violation) as ctx:
            parse_unified_header(b"\x2c\x00")  # S=1 needs 2 seq bytes
        self.assertEqual((ctx.exception.kind, ctx.exception.offset), ("truncation", 1))

    def test_truncated_length_field(self):
        with self.assertRaises(Violation) as ctx:
            parse_unified_header(b"\x2c\x00\x00\x01")  # L=1, only 1 length byte
        self.assertEqual((ctx.exception.kind, ctx.exception.offset), ("truncation", 3))

    def test_declared_length_mismatch(self):
        rec = bytearray(appdata(SECRET3, 3, 0, b"payload"))
        declared = int.from_bytes(rec[3:5], "big")  # S=1: length field at offset 3
        rec[3:5] = (declared - 1).to_bytes(2, "big")
        with self.assertRaises(Violation) as ctx:
            parse_unified_header(bytes(rec))
        self.assertEqual((ctx.exception.kind, ctx.exception.offset), ("length", 3))

    def test_empty_record(self):
        with self.assertRaises(Violation) as ctx:
            parse_unified_header(b"")
        self.assertEqual((ctx.exception.kind, ctx.exception.offset), ("truncation", 0))


class ReceiverRuleTests(unittest.TestCase):
    def test_roundtrip_appdata_and_digest(self):
        rx = Receiver(3, SECRET3)
        row = rx.process_record(appdata(SECRET3, 3, 0, b"hello"))
        self.assertEqual(row["auth"], "ok")
        self.assertEqual(row["replay"], "new")
        self.assertEqual(row["epoch"], 3)
        self.assertEqual(row["seq"], 0)
        self.assertEqual(row["inner_type"], "application_data")
        self.assertEqual(row["app_data_sha256"],
                         hashlib.sha256(b"hello").hexdigest())

    def test_8bit_and_no_length_headers(self):
        rx = Receiver(3, SECRET3)
        row = rx.process_record(appdata(SECRET3, 3, 7, b"a", s_bit=False, l_bit=False))
        self.assertEqual((row["auth"], row["seq"]), ("ok", 7))
        self.assertIsNone(row["header"]["declared_length"])

    def test_failed_auth_never_advances_window(self):
        rx = Receiver(3, SECRET3)
        bad = bytearray(appdata(SECRET3, 3, 0, b"hello"))
        bad[-1] ^= 1
        row = rx.process_record(bytes(bad))
        self.assertEqual(row["violation"]["kind"], "authentication")
        self.assertEqual(row["violation"]["offset"], len(bad) - 16)
        self.assertEqual(rx.current.window.highest, -1)
        self.assertEqual(row["window_before"], row["window_after"])
        # the genuine record is still accepted afterwards
        row2 = rx.process_record(appdata(SECRET3, 3, 0, b"hello"))
        self.assertEqual((row2["replay"], row2["auth"]), ("new", "ok"))

    def test_duplicate_dropped_before_decryption(self):
        rx = Receiver(3, SECRET3)
        rec = appdata(SECRET3, 3, 0, b"hello")
        rx.process_record(rec)
        row = rx.process_record(rec)
        self.assertEqual(row["replay"], "duplicate")
        self.assertEqual(row["auth"], "skipped")
        self.assertEqual(rx.current.window.highest, 0)

    def test_expired_sequence_is_too_old(self):
        rx = Receiver(3, SECRET3)
        rx.process_record(appdata(SECRET3, 3, 64, b"hi"))
        row = rx.process_record(appdata(SECRET3, 3, 0, b"hi"))
        self.assertEqual(row["replay"], "too_old")
        self.assertEqual(row["auth"], "skipped")

    def test_key_update_ratchets_and_resets_window(self):
        rx = Receiver(3, SECRET3)
        rx.process_record(appdata(SECRET3, 3, 0, b"a"))
        row = rx.process_record(key_update_record(SECRET3, 3, 1, request_update=0))
        self.assertEqual(row["key_update"], "processed")
        self.assertEqual(row["auth"], "ok")
        self.assertEqual(rx.current.epoch, 4)
        self.assertEqual(rx.ratchets, 1)
        self.assertEqual(rx.current.window.highest, -1)  # window reset
        self.assertEqual(rx.previous.epoch, 3)           # old keys retained
        secret4 = ratchet_secret(SECRET3)
        row2 = rx.process_record(appdata(secret4, 4, 0, b"post"))
        self.assertEqual((row2["epoch"], row2["replay"], row2["auth"]),
                         (4, "new", "ok"))

    def test_forged_key_update_never_ratchets(self):
        rx = Receiver(3, SECRET3)
        forged = bytearray(key_update_record(SECRET3, 3, 0, request_update=1))
        forged[-1] ^= 0xFF  # corrupt the AEAD tag
        row = rx.process_record(bytes(forged))
        self.assertEqual(row["violation"]["kind"], "authentication")
        self.assertEqual(rx.current.epoch, 3)
        self.assertEqual(rx.ratchets, 0)
        self.assertIsNone(rx.previous)

    def test_duplicate_key_update_does_not_ratchet_twice(self):
        rx = Receiver(3, SECRET3)
        ku = key_update_record(SECRET3, 3, 0)
        rx.process_record(ku)
        row = rx.process_record(ku)  # replayed capture of the same KeyUpdate
        self.assertEqual(row["replay"], "duplicate")
        self.assertEqual(rx.current.epoch, 4)
        self.assertEqual(rx.ratchets, 1)

    def test_old_epoch_key_update_ignored(self):
        rx = Receiver(3, SECRET3)
        rx.process_record(key_update_record(SECRET3, 3, 0))  # -> epoch 4
        late = key_update_record(SECRET3, 3, 5)              # straggler in epoch 3
        row = rx.process_record(late)
        self.assertEqual(row["epoch"], 3)
        self.assertEqual(row["auth"], "ok")
        self.assertEqual(row["key_update"], "ignored_old_epoch")
        self.assertEqual(rx.current.epoch, 4)
        self.assertEqual(rx.ratchets, 1)

    def test_old_epoch_record_never_slides_current_window(self):
        rx = Receiver(3, SECRET3)
        rx.process_record(key_update_record(SECRET3, 3, 0))  # -> epoch 4
        before = rx.current.window.snapshot()
        row = rx.process_record(appdata(SECRET3, 3, 1, b"late"))
        self.assertEqual((row["epoch"], row["replay"]), (3, "new"))
        self.assertEqual(rx.current.window.snapshot(), before)
        self.assertEqual(rx.previous.window.highest, 1)  # own epoch window only

    def test_old_epoch_replay_still_detected(self):
        rx = Receiver(3, SECRET3)
        rec = appdata(SECRET3, 3, 0, b"a")
        rx.process_record(rec)
        rx.process_record(key_update_record(SECRET3, 3, 1))  # -> epoch 4
        row = rx.process_record(rec)  # replayed old-epoch capture
        self.assertEqual(row["replay"], "duplicate")

    def test_future_epoch_rejected_as_state_violation(self):
        rx = Receiver(3, SECRET3)
        secret4 = ratchet_secret(SECRET3)
        row = rx.process_record(appdata(secret4, 4, 0, b"x"))
        self.assertEqual(row["violation"]["kind"], "state")
        self.assertEqual(row["violation"]["offset"], 0)
        self.assertEqual(rx.ratchets, 0)

    def test_short_ciphertext_is_length_violation(self):
        rx = Receiver(3, SECRET3)
        rec = bytes([0x2B, 0x00, 0x00]) + b"\x00" * 5  # S=1, L=0, E=3, 5 < 16
        row = rx.process_record(rec)
        self.assertEqual(row["violation"]["kind"], "length")
        self.assertEqual(row["violation"]["offset"], 3)

    def test_empty_inner_plaintext_is_length_violation(self):
        key, iv = derive_record_keys(SECRET3)
        hdr = bytes([0x2F, 0x00, 0x00, 0x00, 0x10])  # S=1, L=1, E=3, len=16
        ct = AESGCM(key).encrypt(record_nonce(iv, 0), b"", hdr)
        row = Receiver(3, SECRET3).process_record(hdr + ct)
        self.assertEqual(row["violation"]["kind"], "length")

    def test_malformed_key_update_body_no_ratchet(self):
        from server.encode import handshake_message
        bad_hs = handshake_message(24, b"\x07\x08")  # invalid request_update
        rec = seal_record(SECRET3, 3, 0, bad_hs, 22)
        rx = Receiver(3, SECRET3)
        row = rx.process_record(rec)
        self.assertEqual(row["violation"]["kind"], "state")
        self.assertEqual(rx.ratchets, 0)
        # record was authenticated, so its sequence is marked received
        self.assertEqual(rx.current.window.highest, 0)

    def test_inner_type_unwrapped_only_after_auth(self):
        # a record with a valid header but garbage ciphertext must not
        # reveal any inner content type
        rx = Receiver(3, SECRET3)
        rec = bytes([0x2F, 0x00, 0x00, 0x00, 0x14]) + b"\xaa" * 20
        row = rx.process_record(rec)
        self.assertEqual(row["violation"]["kind"], "authentication")
        self.assertIsNone(row["inner_type"])


class TraceEvidenceTests(unittest.TestCase):
    """Frozen per-record placeholder evidence for duplicate/too-old calls."""

    def _audit(self, blobs):
        return run_audit(3, SECRET3, blobs)

    def test_duplicate_points_at_first_authenticated_originator(self):
        v = self._audit([
            appdata(SECRET3, 3, 5, b"a"),
            appdata(SECRET3, 3, 3, b"b"),
            appdata(SECRET3, 3, 3, b"b"),  # replay of record #1
        ])
        t = v["records"][2]["trace"]
        self.assertEqual(t["replay"], "duplicate")
        self.assertEqual(t["auth"], "skipped")
        self.assertEqual(t["epoch"], 3)
        self.assertEqual(t["seq"], 3)
        # adjudication snapshot: highest 5, bitmap has bits 0 and 2 set
        w = t["adjudication_window"]
        self.assertEqual((w["highest"], w["epoch"]), (5, 3))
        self.assertEqual(w["lower_bound"], 5 - 63)
        self.assertEqual(t["distance"], 2)
        self.assertEqual(t["bit_evidence"]["within_window"], True)
        self.assertEqual(t["bit_evidence"]["bit_offset"], 2)
        self.assertEqual(t["bit_evidence"]["bit_value"], 1)
        self.assertTrue(t["traceable_placeholder"])
        self.assertEqual(t["originator"],
                         {"record_index": 1, "epoch": 3, "seq": 3, "auth": "ok"})

    def test_too_old_gives_boundary_without_fabricated_placeholder(self):
        v = self._audit([
            appdata(SECRET3, 3, 64, b"hi"),
            appdata(SECRET3, 3, 0, b"hi"),  # offset 64 -> expired
        ])
        t = v["records"][1]["trace"]
        self.assertEqual(t["replay"], "too_old")
        w = t["adjudication_window"]
        self.assertEqual(w["highest"], 64)
        self.assertEqual(w["lower_bound"], 1)
        self.assertEqual(t["distance"], 64)
        self.assertFalse(t["bit_evidence"]["within_window"])
        self.assertEqual(t["bit_evidence"]["bit_value"], None)
        self.assertIsNone(t["originator"])
        self.assertFalse(t["traceable_placeholder"])

    def test_sliding_window_cannot_overwrite_frozen_duplicate_trace(self):
        v = self._audit([
            appdata(SECRET3, 3, 0, b"a"),
            appdata(SECRET3, 3, 0, b"a"),   # duplicate at highest 0
            appdata(SECRET3, 3, 100, b"b"),  # slides the old bit out
        ])
        # the final window no longer covers seq 0...
        self.assertEqual(v["final_state"]["epochs"][-1]["highest"], 100)
        # ...but the frozen trace of record #1 keeps its original verdict
        t = v["records"][1]["trace"]
        self.assertEqual(t["replay"], "duplicate")
        self.assertEqual(t["adjudication_window"]["highest"], 0)
        self.assertEqual(t["adjudication_window"]["bitmap"], "0000000000000001")
        self.assertEqual(t["distance"], 0)
        self.assertEqual(t["bit_evidence"]["bit_value"], 1)
        self.assertEqual(t["originator"]["record_index"], 0)
        self.assertTrue(t["traceable_placeholder"])

    def test_new_record_has_no_traceable_placeholder(self):
        v = self._audit([appdata(SECRET3, 3, 7, b"a")])
        t = v["records"][0]["trace"]
        self.assertEqual(t["replay"], "new")
        self.assertEqual(t["auth"], "ok")
        self.assertIsNone(t["originator"])
        self.assertFalse(t["traceable_placeholder"])
        self.assertEqual(t["adjudication_window"]["highest"], -1)

    def test_authentication_failure_has_no_traceable_placeholder(self):
        tampered = bytearray(appdata(SECRET3, 3, 2, b"y"))
        tampered[-1] ^= 1
        v = self._audit([
            appdata(SECRET3, 3, 64, b"x"),
            bytes(tampered),                 # new bit, but AEAD fails
            appdata(SECRET3, 3, 2, b"y"),   # still new afterwards
        ])
        t = v["records"][1]["trace"]
        self.assertEqual(t["replay"], "new")
        self.assertEqual(t["auth"], "failed")
        self.assertEqual(t["bit_evidence"]["bit_value"], 0)
        self.assertIsNone(t["originator"])
        self.assertFalse(t["traceable_placeholder"])
        # the genuine record arriving later is still new
        self.assertEqual(v["records"][2]["trace"]["replay"], "new")

    def test_traces_do_not_change_existing_verdict_fields(self):
        v = self._audit([
            appdata(SECRET3, 3, 0, b"a"),
            key_update_record(SECRET3, 3, 1),
        ])
        self.assertTrue(v["ok"])
        self.assertIsNone(v["first_violation"])
        self.assertEqual(v["final_state"]["current_epoch"], 4)
        self.assertEqual(v["final_state"]["ratchets"], 1)
        for r in v["records"]:
            for key in ("index", "epoch", "seq", "replay", "auth",
                        "window_before", "window_after", "violation"):
                self.assertIn(key, r)
            self.assertIn("trace", r)


if __name__ == "__main__":
    unittest.main()
