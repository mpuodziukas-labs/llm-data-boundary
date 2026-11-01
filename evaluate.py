#!/usr/bin/env python3
"""Run boundary.py decide over every case in cases/ and compare with expected.json.
Each case also verifies the evidence chain it wrote."""
import contextlib
import io
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "cases")
sys.path.insert(0, HERE)
import boundary  # noqa: E402


def run_case(name):
    """Return (want_text, got_text, ok). A crash is a mismatch, never a pass."""
    folder = os.path.join(CASES, name)
    try:
        with open(os.path.join(folder, "expected.json"), encoding="utf-8") as fh:
            exp = json.load(fh)
        want = "exit=%s %s %s %s" % (exp["exit"], exp["decision"], exp["rule"],
                                     json.dumps(exp["classes"], sort_keys=True))
    except (OSError, ValueError, KeyError) as exc:
        return "unreadable expected.json", "ERROR " + type(exc).__name__, False
    try:
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "evidence.jsonl")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
                rc = boundary.main(["decide", os.path.join(folder, "request.json"),
                                    "--registry", os.path.join(folder, "registry.json"),
                                    "--log", log, "--now", exp["now"]])
            if rc == 2:
                got_dec, got_rule, got_cls, red = None, None, {}, None
                wrote = os.path.exists(log)
                chain_ok = not wrote
            else:
                out = json.loads(buf.getvalue())
                got_dec, got_rule, got_cls, red = out["decision"], out["rule"], out["classes"], out["redacted_payload"]
                with open(log, "rb") as fh:
                    chain_ok = boundary.verify_bytes(fh.read())[0]
            got = "exit=%s %s %s %s" % (rc, got_dec, got_rule, json.dumps(got_cls, sort_keys=True))
            ok = got == want and chain_ok and red == exp.get("redacted_payload")
            if not chain_ok:
                got += " CHAIN-BAD"
            if red != exp.get("redacted_payload"):
                got += " REDACTION-DIFFERS"
    except Exception as exc:  # noqa: BLE001
        return want, "ERROR " + type(exc).__name__, False
    return want, got, ok


def main():
    if len(sys.argv) > 1:
        print("usage: python3 evaluate.py (takes no arguments)", file=sys.stderr)
        return 2
    names = sorted(n for n in os.listdir(CASES) if os.path.isdir(os.path.join(CASES, n)))
    rows, matched = [], 0
    print("| case | expected | got | match |")
    print("|---|---|---|---|")
    for n in names:
        want, got, ok = run_case(n)
        matched += ok
        rows.append({"case": n, "expected": want, "got": got, "match": ok})
        print("| %s | %s | %s | %s |" % (n, want, got, "yes" if ok else "NO"))
    with open(os.path.join(HERE, "PROOF.json"), "w", encoding="utf-8") as fh:
        json.dump({"matched": matched, "total": len(names), "cases": rows}, fh, indent=2)
        fh.write("\n")
    print()
    print("cases: %d/%d match" % (matched, len(names)))
    return 0 if names and matched == len(names) else 1


if __name__ == "__main__":
    sys.exit(main())
