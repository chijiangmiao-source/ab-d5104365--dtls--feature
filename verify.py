#!/usr/bin/env python3
"""Acceptance driver for the DTLS 1.3 audit service.

Runs, in order:
  1. build checks        — byte-compile the app, import it, sanity-check the page
  2. review-rule tests   — the unittest suite (replay window, KeyUpdate, vectors)
  3. HTTP smoke tests    — live API checks of the KeyUpdate ratchet and the
                           replay-window boundary against APP_BASE_URL

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

    # --- scenario E: frozen placeholder traceability via the real API ---
    # records: #0 seq0 new, #1 seq0 duplicate, #2 seq100 new (window slides
    # and pushes the seq0 bit out), #3 seq0 too old, #4 seq36 (offset 64
    # -> too old relative to highest 100), #5 seq37 (offset 63) new but
    # with a corrupted tag.
    tampered = bytearray(app(37))
    tampered[-1] ^= 1
    records = [
        app(0),
        app(0),
        app(100),
        app(0),
        app(36),
        bytes(tampered),
    ]
    status, v = post_audit("smoke-trace", secret_hex, records)
    if status != 200:
        check("trace: submission accepted", False, f"status {status}")
    else:
        def trace(index):
            return http("GET", f"/api/audit/smoke-trace/record/{index}/trace")

        # duplicate: real interface names the first authenticated originator
        st, body = trace(1)
        t = (body or {}).get("trace", {})
        ok = (st == 200 and t.get("replay") == "duplicate"
              and t.get("epoch") == 3 and t.get("seq") == 0
              and t.get("auth") == "skipped")
        check("trace: duplicate returns recovered seq/epoch/adjudication",
              ok, f"{st} {json.dumps(body)[:240]}" if not ok else "")
        check("trace: duplicate bit evidence at adjudication time",
              t.get("adjudication_window", {}).get("highest") == 0
              and t.get("distance") == 0
              and (t.get("bit_evidence") or {}).get("bit_offset") == 0
              and (t.get("bit_evidence") or {}).get("bit_value") == 1,
              json.dumps(t)[:240])
        check("trace: duplicate names first authenticated originator",
              (t.get("originator") or {}).get("record_index") == 0
              and t["originator"].get("seq") == 0
              and t["originator"].get("auth") == "ok"
              and t.get("traceable_placeholder") is True,
              json.dumps(t)[:240])

        # after the window slides, requerying the earlier duplicate must
        # still answer from the frozen snapshot rather than the final window
        st, body2 = trace(1)
        t2 = (body2 or {}).get("trace", {})
        check("trace: window slide does not overwrite frozen duplicate",
              st == 200
              and t2.get("replay") == "duplicate"
              and t2.get("adjudication_window", {}).get("highest") == 0
              and t2.get("adjudication_window", {}).get("bitmap") ==
                  "0000000000000001"
              and v["final_state"]["epochs"][-1]["highest"] == 100
              and t2 == t,
              f"final highest=100 but trace={json.dumps(t2)[:200]}")

        # too old: highest, distance and window lower bound; no placeholder
        st, body = trace(3)
        t = (body or {}).get("trace", {})
        check("trace: too-old gives highest/distance/lower bound",
              st == 200 and t.get("replay") == "too_old"
              and t.get("adjudication_window", {}).get("highest") == 100
              and t.get("distance") == 100
              and t.get("adjudication_window", {}).get("lower_bound") == 37,
              json.dumps(t)[:240])
        check("trace: too-old fabricates no placeholder record",
              (t.get("bit_evidence") or {}).get("within_window") is False
              and t.get("originator") is None
              and t.get("traceable_placeholder") is False,
              json.dumps(t)[:240])

        # the offset-64 boundary record: lower bound 37 means seq 36 is out
        st, body = trace(4)
        t = (body or {}).get("trace", {})
        check("trace: offset 64 beyond window lower bound 37",
              st == 200 and t.get("replay") == "too_old"
              and t.get("distance") == 64
              and t.get("adjudication_window", {}).get("lower_bound") == 37
              and t.get("bit_evidence", {}).get("bit_value") is None,
              json.dumps(t)[:240])

        # authentication failure: adjudicated new, but no placeholder exists
        st, body = trace(5)
        t = (body or {}).get("trace", {})
        check("trace: failed-auth record has no traceable placeholder",
              st == 200 and t.get("replay") == "new" and t.get("auth") == "failed"
              and (t.get("bit_evidence") or {}).get("bit_offset") == 63
              and (t.get("bit_evidence") or {}).get("bit_value") == 0
              and t.get("originator") is None
              and t.get("traceable_placeholder") is False,
              json.dumps(t)[:240])

        # the fresh record likewise has no placeholder to trace
        st, body = trace(0)
        t = (body or {}).get("trace", {})
        check("trace: new record explicitly has no placeholder",
              st == 200 and t.get("replay") == "new"
              and t.get("traceable_placeholder") is False
              and t.get("originator") is None,
              json.dumps(t)[:200])

        # frozen evidence survives reopening by audit id
        st, reopened = http("GET", "/api/audit/smoke-trace")
        st2, body = trace(1)
        check("trace: evidence intact after verdict reopen",
              st == 200 and reopened.get("record_count") == 6
              and st2 == 200
              and (body.get("trace") or {}).get("replay") == "duplicate",
              f"{st} {st2}")

        # error paths: unknown audit id and out-of-range / negative index
        st, body = http("GET", "/api/audit/no-such-audit/record/0/trace")
        check("trace: unknown audit id is 404", st == 404, f"status {st}")
        st, body = trace(99)
        check("trace: out-of-range index is 404", st == 404, f"status {st}")
        st, body = http("GET", "/api/audit/smoke-trace/record/-1/trace")
        # FastAPI rejects the negative segment as a different route -> 404
        check("trace: negative index not accepted", st == 404, f"status {st}")


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
