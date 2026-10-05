#!/usr/bin/env python3
"""Acceptance driver for the DTLS 1.3 audit service.

Runs, in order:
  1. build checks        — byte-compile the app, import it, sanity-check the page
  2. review-rule tests   — the unittest suite (replay window, KeyUpdate, vectors)
  3. HTTP smoke tests    — live API checks of the KeyUpdate ratchet, the
                           replay-window boundary, and the per-record
                           duplicate/too-old trace interface against
                           APP_BASE_URL

Exits 0 when every check passes, 1 otherwise, so `docker compose up
--exit-code-from verify` reports the acceptance result as its status code.
"""
import base64
import compileall
import json
import os
import sys
import unittest
import urllib.error
import urllib.request

APP_BASE = os.environ.get("APP_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
FAILURES: list[str] = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(f"{name}: {detail}")
    return cond


# ---------------------------------------------------------------- build checks
def build_checks():
    print("[verify] build checks")
    check("compileall server", compileall.compile_dir("server", quiet=1))
    check("compileall tests", compileall.compile_dir("tests", quiet=1))
    try:
        import server.main  # noqa: F401
        check("import server.main", True)
    except Exception as exc:  # pragma: no cover
        check("import server.main", False, repr(exc))
    try:
        with open("server/static/index.html", encoding="utf-8") as fh:
            html = fh.read()
        check("page contains audit form",
              all(token in html for token in ("audit_id", "traffic_secret", "records")))
    except OSError as exc:
        check("page contains audit form", False, repr(exc))


# ------------------------------------------------------------ review-rule tests
def review_rule_tests():
    print("[verify] review-rule tests")
    suite = unittest.TestLoader().discover("tests")
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    check("review-rule test suite", result.wasSuccessful(),
          f"{len(result.failures)} failure(s), {len(result.errors)} error(s)")


# ---------------------------------------------------------------- HTTP helpers
def http(method, path, payload=None):
    data = headers = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
    req = urllib.request.Request(APP_BASE + path, data=data,
                                 headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, _maybe_json(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, _maybe_json(exc.read())


def _maybe_json(raw: bytes):
    try:
        return json.loads(raw.decode())
    except Exception:
        return raw.decode(errors="replace")


def b64(blob):
    return base64.b64encode(blob).decode()


def post_audit(audit_id, secret_hex, records, initial_epoch=3):
    return http("POST", "/api/audit", {
        "audit_id": audit_id,
        "initial_epoch": initial_epoch,
        "traffic_secret": secret_hex,
        "records": [b64(r) for r in records],
    })


def viol(row):
    return row.get("violation") or {}


# ------------------------------------------------------------------ smoke tests
def smoke_tests():
    from server.crypto import ratchet_secret
    from server.encode import key_update_record, seal_record

    print(f"[verify] HTTP smoke tests against {APP_BASE}")

    status, body = http("GET", "/healthz")
    check("health endpoint", status == 200 and body.get("status") == "ok",
          f"{status} {body}")
    status, _ = http("GET", "/")
    check("audit page served", status == 200, f"status {status}")

    secret3 = bytes(range(32))
    secret4 = ratchet_secret(secret3)
    secret_hex = secret3.hex()

    def app(seq, payload=b"m", secret=secret3, epoch=3, tamper=False):
        rec = bytearray(seal_record(secret, epoch, seq, payload, 23))
        if tamper:
            rec[-1] ^= 1
        return bytes(rec)

    # --- scenario A: legal KeyUpdate ratchets epoch and resets the window ---
    records = [
        app(0, b"ping-0"),
        app(1, b"ping-1"),
        key_update_record(secret3, 3, 2, request_update=0),
        seal_record(secret4, 4, 0, b"post-update", 23),
        app(1, b"ping-1"),  # late replay in the old epoch
    ]
    status, v = post_audit("smoke-keyupdate", secret_hex, records)
    ok = status == 200 and v.get("ok") is True
    check("keyupdate: submission accepted without violations", ok,
          f"{status} {json.dumps(v)[:300]}" if not ok else "")
    if status == 200:
        recs = v["records"]
        check("keyupdate: KeyUpdate processed after authentication",
              recs[2]["key_update"] == "processed" and recs[2]["auth"] == "ok")
        check("keyupdate: ratchet advanced to epoch 4",
              v["final_state"]["current_epoch"] == 4
              and v["final_state"]["ratchets"] == 1)
        check("keyupdate: next-epoch record adjudicated new",
              recs[3]["epoch"] == 4 and recs[3]["replay"] == "new")
        check("keyupdate: old-epoch replay adjudicated duplicate",
              recs[4]["replay"] == "duplicate" and recs[4]["epoch"] == 3)
        check("keyupdate: new epoch window reset then advanced",
              any(e["epoch"] == 4 and e["highest"] == 0
                  and e["bitmap"] == "0000000000000001"
                  for e in v["final_state"]["epochs"]))
    status, v2 = http("GET", "/api/audit/smoke-keyupdate")
    check("keyupdate: frozen verdict reopens",
          status == 200 and v2.get("ok") is True and v2.get("record_count") == 5,
          f"status {status}")

    # --- scenario B: replay-window boundary (64-bit bitmap) ---
    records = [
        app(0),                 # new
        app(0),                 # duplicate
        app(64),                # new, jumps the window
        app(0),                 # offset 64 -> too old
        app(1),                 # offset 63 -> new
        app(2, tamper=True),    # AEAD failure, must not advance the window
        app(2),                 # still new after the failed forgery
    ]
    status, v = post_audit("smoke-replay", secret_hex, records)
    if status != 200:
        check("replay: submission accepted", False, f"status {status}")
    else:
        recs = v["records"]
        check("replay: fresh record is new", recs[0]["replay"] == "new")
        check("replay: exact replay is duplicate", recs[1]["replay"] == "duplicate")
        check("replay: jump to 64 is new", recs[2]["replay"] == "new")
        check("replay: offset 64 is too old", recs[3]["replay"] == "too_old")
        check("replay: offset 63 is new", recs[4]["replay"] == "new")
        check("replay: tampered record fails authentication",
              viol(recs[5]).get("kind") == "authentication")
        check("replay: authentication failure offset points at the tag",
              viol(recs[5]).get("offset") == len(records[5]) - 16)
        check("replay: failed record did not advance the window",
              recs[5]["window_before"] == recs[5]["window_after"])
        check("replay: genuine seq 2 still new after the failure",
              recs[6]["replay"] == "new")
        fv = v.get("first_violation") or {}
        check("replay: first violation reported with raw offset",
              fv.get("record_index") == 5 and fv.get("kind") == "authentication"
              and fv.get("offset") == len(records[5]) - 16)

    # --- scenario C: forged KeyUpdate never ratchets; stale success cleared ---
    status, v = post_audit("smoke-forged-ku", secret_hex, [app(0), app(1)])
    check("forged-ku: clean submission succeeds first",
          status == 200 and v.get("ok") is True,
          f"{status} {json.dumps(v)[:200]}" if not (status == 200 and v.get("ok")) else "")
    forged = bytearray(key_update_record(secret3, 3, 1, request_update=1))
    forged[-1] ^= 0x80  # corrupt the tag: a forged KeyUpdate
    records = [app(0), bytes(forged), seal_record(secret4, 4, 0, b"next", 23)]
    status, v = post_audit("smoke-forged-ku", secret_hex, records)
    if status != 200:
        check("forged-ku: resubmission accepted", False, f"status {status}")
    else:
        recs = v["records"]
        check("forged-ku: verdict reports violations", v.get("ok") is False)
        check("forged-ku: forged KeyUpdate fails authentication",
              viol(recs[1]).get("kind") == "authentication")
        check("forged-ku: secret and window never advance",
              v["final_state"]["current_epoch"] == 3
              and v["final_state"]["ratchets"] == 0)
        check("forged-ku: next-epoch record rejected as state violation",
              viol(recs[2]).get("kind") == "state")
    status, v = http("GET", "/api/audit/smoke-forged-ku")
    check("forged-ku: stale success evidence cleared on resubmission",
          status == 200 and v.get("ok") is False, f"status {status}")

    # --- scenario D: truncation / length violations carry raw offsets ---
    status, v = post_audit("smoke-trunc", secret_hex, [bytes([0x2C, 0x00])])
    fv = (v or {}).get("first_violation") or {}
    check("truncation: kind and raw offset reported",
          status == 200 and fv.get("kind") == "truncation" and fv.get("offset") == 1,
          f"{status} {fv}")

    rec = bytearray(seal_record(secret3, 3, 0, b"xyz", 23))  # S=1,L=1: length @3
    declared = int.from_bytes(rec[3:5], "big")
    rec[3:5] = (declared - 1).to_bytes(2, "big")
    status, v = post_audit("smoke-length", secret_hex, [bytes(rec)])
    fv = (v or {}).get("first_violation") or {}
    check("length: kind and raw offset reported",
          status == 200 and fv.get("kind") == "length" and fv.get("offset") == 3,
          f"{status} {fv}")

    # --- scenario E: duplicate / too-old traceability across a window shift ---
    records = [
        app(0),                 # 0: new, first occupies the bit for seq 0
        app(0),                 # 1: duplicate of seq 0
        app(2),                 # 2: new
        app(3, tamper=True),    # 3: AEAD failure, never occupies a bit
        app(70),                # 4: new; 68-step shift evicts the seq 0/2 bits
        app(0),                 # 5: offset 70 -> too old
        app(69),                # 6: offset 1 -> new
        app(70),                # 7: duplicate of seq 70
    ]
    status, v = post_audit("smoke-trace", secret_hex, records)
    if status != 200:
        check("trace: submission accepted", False, f"status {status}")
    else:
        check("trace: tampered record flags the verdict", v.get("ok") is False)

        def trace(idx, audit_id="smoke-trace"):
            return http("GET", f"/api/audit/{audit_id}/records/{idx}/trace")

        status, t = trace(1)
        ok = (status == 200 and t.get("replay") == "duplicate"
              and t.get("epoch") == 3 and t.get("seq") == 0
              and t.get("highest_at_decision") == 0
              and t.get("bit_offset") == 0 and t.get("bit_value") == 1)
        check("trace: duplicate resolved against decision-time window", ok,
              f"{status} {json.dumps(t)[:300]}" if not ok else "")
        setter = ((t or {}).get("placeholder") or {}).get("first_set_by") or {}
        check("trace: duplicate placeholder names first authenticating record",
              setter.get("record_index") == 0 and setter.get("seq") == 0
              and setter.get("auth") == "ok", json.dumps(setter))

        status, t = trace(5)
        ok = (status == 200 and t.get("replay") == "too_old"
              and t.get("highest_at_decision") == 70 and t.get("gap") == 70
              and t.get("window_lowest") == 7)
        check("trace: too-old reports highest, gap and window lower bound", ok,
              f"{status} {json.dumps(t)[:300]}" if not ok else "")
        check("trace: too-old fabricates no placeholder record",
              status == 200 and t.get("placeholder") is None)

        # the seq-0/2 bits were evicted by the jump to 70; the frozen
        # per-record snapshot must still answer, not the final window
        status, t = trace(0)
        check("trace: evicted bit keeps frozen decision (no final-window backfill)",
              status == 200 and t.get("replay") == "new"
              and t.get("highest_at_decision") == -1
              and t.get("placeholder") is None,
              f"{status} {json.dumps(t)[:300]}")
        status, t = trace(2)
        check("trace: evicted new record keeps decision-time highest",
              status == 200 and t.get("replay") == "new"
              and t.get("highest_at_decision") == 0
              and t.get("placeholder") is None,
              f"{status} {json.dumps(t)[:300]}")

        status, t = trace(3)
        check("trace: authentication failure has no traceable placeholder",
              status == 200 and t.get("replay") == "new"
              and t.get("placeholder") is None and bool(t.get("note")),
              f"{status} {json.dumps(t)[:300]}")

        status, t = trace(6)
        check("trace: in-window new record shows unset bit at decision",
              status == 200 and t.get("bit_offset") == 1
              and t.get("bit_value") == 0 and t.get("placeholder") is None,
              f"{status} {json.dumps(t)[:300]}")

        status, t = trace(7)
        setter = ((t or {}).get("placeholder") or {}).get("first_set_by") or {}
        check("trace: post-shift duplicate traces to its original record",
              status == 200 and t.get("highest_at_decision") == 70
              and setter.get("record_index") == 4 and setter.get("auth") == "ok",
              f"{status} {json.dumps(t)[:300]}")

        status, _ = trace(8)
        check("trace: out-of-range record index rejected", status == 404,
              f"status {status}")
        status, _ = trace(0, audit_id="smoke-missing")
        check("trace: unknown audit id rejected", status == 404,
              f"status {status}")


def main():
    print(f"[verify] acceptance run, target {APP_BASE}")
    build_checks()
    review_rule_tests()
    smoke_tests()
    if FAILURES:
        print("[verify] failures:")
        for failure in FAILURES:
            print("  -", failure)
    print("[verify] ACCEPTANCE:", "PASS" if not FAILURES else "FAIL")
    sys.exit(0 if not FAILURES else 1)


if __name__ == "__main__":
    main()
