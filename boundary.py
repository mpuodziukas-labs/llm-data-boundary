#!/usr/bin/env python3
"""llm-data-boundary: policy-as-code gate in front of an LLM provider.

    python3 boundary.py decide REQUEST.json --registry REGISTRY.json --log EVIDENCE.jsonl [--now YYYY-MM-DD]
    python3 boundary.py verify EVIDENCE.jsonl [--head SHA256]

Exit codes: 0 allow (ALLOW or REDACT-THEN-ALLOW, or chain verified), 1 deny or refuse,
2 bad input (file missing, not JSON, duplicate keys, bad date). Standard library only.
All data in this repository is synthetic.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import re
import sys
import unicodedata
from typing import Any, Callable, Dict, List, Optional, Tuple

try:  # POSIX file lock; absent on some platforms, the chain check still holds
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore

ALLOW = "ALLOW"
REDACT = "REDACT-THEN-ALLOW"
DENY = "DENY"
DECISIONS = (ALLOW, REDACT, DENY)

MAX_ATTEST_AGE_DAYS = 180
ALLOWED_REGIONS = ("us", "eu")
ENTROPY_MIN_LEN = 24
ENTROPY_THRESHOLD = 4.0
GENESIS = "0" * 64

VALID_LABELS = ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "CUSTOMER_DATA")
REQUEST_KEYS = ("app", "labels", "payload", "provider")
PROVIDER_FIELDS: Dict[str, type] = {
    "trains_on_inputs": bool,
    "zero_data_retention": bool,
    "retention_days": int,
    "region": str,
    "contract_signed": bool,
    "attested_on": str,
}
RECORD_KEYS = ("app", "classes", "decision", "hash", "labels", "now", "prev",
               "provider", "provider_attrs", "rule", "seq")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


# ---------------------------------------------------------------- classifier

def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _card_ok(m: "re.Match[str]") -> bool:
    digits = re.sub(r"\D", "", m.group(0))
    return 13 <= len(digits) <= 19 and luhn_ok(digits)


def _ssn_ok(m: "re.Match[str]") -> bool:
    area, group, serial = m.group(1), m.group(2), m.group(3)
    if area in ("000", "666") or area.startswith("9"):
        return False
    return group != "00" and serial != "0000"


def shannon(s: str) -> float:
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


def _entropy_ok(m: "re.Match[str]") -> bool:
    tok = m.group(0)
    return (any(c.isdigit() for c in tok) and any(c.isalpha() for c in tok)
            and shannon(tok) >= ENTROPY_THRESHOLD)


# (class, regex, validator). Order matters: the first pattern to claim text wins.
PATTERNS: List[Tuple[str, "re.Pattern[str]", Optional[Callable[["re.Match[str]"], bool]]]] = [
    ("SECRET_PRIVATE_KEY", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"), None),
    ("SECRET_AWS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), None),
    ("SECRET_BEARER", re.compile(r"\b[Bb]earer\s+[A-Za-z0-9._~+/\-]{16,}=*"), None),
    ("PII_CARD", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), _card_ok),
    ("PII_SSN", re.compile(r"(?<!\d)(\d{3})-(\d{2})-(\d{4})(?!\d)"), _ssn_ok),
    ("PII_EMAIL", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), None),
    ("PII_PHONE", re.compile(r"(?<!\d)(?:\+?1[ .\-]?)?(?:\(\d{3}\)|\d{3})[ .\-]?\d{3}[ .\-]\d{4}(?!\d)"), None),
    ("SECRET_ENTROPY", re.compile(r"[A-Za-z0-9+/_\-]{%d,}" % ENTROPY_MIN_LEN), _entropy_ok),
]
TEXT_LABEL_RE = re.compile(r"\b(CONFIDENTIAL|INTERNAL|RESTRICTED)\b")
CUSTOMER_RE = re.compile(r"\bcustomer[ _\-]data\b", re.IGNORECASE)


def normalize(text: str) -> str:
    """NFKC, then drop Unicode format characters (category Cf: zero-width space and joiners,
    word joiner, byte order mark, soft hyphen). Matching and redaction both run on this text."""
    text = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def scan(text: str) -> Tuple[Dict[str, int], str]:
    """Return (class -> count, text with every match replaced by [REDACTED:CLASS])."""
    text = normalize(text)
    counts: Dict[str, int] = {}
    for cls, rx, check in PATTERNS:
        def repl(m: "re.Match[str]", cls: str = cls, check=check) -> str:
            if check is not None and not check(m):
                return m.group(0)
            counts[cls] = counts.get(cls, 0) + 1
            return "[REDACTED:%s]" % cls
        text = rx.sub(repl, text)
    return counts, text


def classify(text: str) -> Dict[str, int]:
    return scan(text)[0]


def redact(text: str) -> str:
    return scan(text)[1]


def text_labels(text: str) -> List[str]:
    text = normalize(text)
    found = set(TEXT_LABEL_RE.findall(text))
    if CUSTOMER_RE.search(text):
        found.add("CUSTOMER_DATA")
    return sorted(found)


# ------------------------------------------------------------------- policy

def validate_request(req: Any) -> Optional[str]:
    if not isinstance(req, dict):
        return "request is not an object"
    if tuple(sorted(req)) != REQUEST_KEYS:
        return "request keys must be exactly " + ",".join(REQUEST_KEYS)
    for k in ("provider", "app"):
        if not isinstance(req[k], str) or not req[k].strip():
            return k + " must be a non-empty string"
    if not isinstance(req["payload"], str):
        return "payload must be a string"
    labels = req["labels"]
    if not isinstance(labels, list) or any(not isinstance(x, str) or x not in VALID_LABELS for x in labels):
        return "labels must be a list of known labels"
    return None


def validate_provider(entry: Any) -> Optional[str]:
    if not isinstance(entry, dict):
        return "provider entry is not an object"
    for name, typ in PROVIDER_FIELDS.items():
        if name not in entry:
            return "missing field " + name
        v = entry[name]
        if isinstance(v, bool) != (typ is bool):
            return "wrong type for " + name
        if not isinstance(v, typ):
            return "wrong type for " + name
    if entry["retention_days"] < 0:
        return "negative retention_days"
    if not DATE_RE.match(entry["attested_on"]):
        return "attested_on is not YYYY-MM-DD"
    try:
        dt.date.fromisoformat(entry["attested_on"])
    except ValueError:
        return "attested_on is not a real date"
    if entry["zero_data_retention"] and entry["retention_days"] != 0:
        return "zero_data_retention contradicts retention_days"
    return None


def _result(decision: str, rule: str, classes: Dict[str, int], labels: List[str],
            attrs: Optional[Dict[str, Any]] = None, redacted: Optional[str] = None) -> Dict[str, Any]:
    return {"decision": decision, "rule": rule, "classes": dict(sorted(classes.items())),
            "labels": labels, "provider_attrs": attrs, "redacted_payload": redacted}


def decide(request: Any, registry: Any, today: dt.date) -> Dict[str, Any]:
    """Pure policy. First matching rule wins. Anything unclear is DENY."""
    err = validate_request(request)
    if err:
        return _result(DENY, "R01_MALFORMED_REQUEST", {}, [])
    payload: str = request["payload"]
    classes = classify(payload)
    labels = sorted(set(request["labels"]) | set(text_labels(payload)))
    providers = registry.get("providers") if isinstance(registry, dict) else None
    if not isinstance(providers, dict):
        return _result(DENY, "R03_REGISTRY_INVALID", classes, labels)
    entry = providers.get(request["provider"])
    if entry is None:
        return _result(DENY, "R02_UNKNOWN_PROVIDER", classes, labels)
    if validate_provider(entry):
        return _result(DENY, "R03_REGISTRY_INVALID", classes, labels)
    attrs = {k: entry[k] for k in sorted(PROVIDER_FIELDS)}

    def out(decision: str, rule: str, redacted: Optional[str] = None) -> Dict[str, Any]:
        return _result(decision, rule, classes, labels, attrs, redacted)

    age = (today - dt.date.fromisoformat(entry["attested_on"])).days
    if age < 0:
        return out(DENY, "R04_ATTESTATION_FUTURE")
    if age > MAX_ATTEST_AGE_DAYS:
        return out(DENY, "R04_ATTESTATION_STALE")

    secret = any(c.startswith("SECRET_") for c in classes)
    pii = any(c.startswith("PII_") for c in classes)
    restricted = "RESTRICTED" in labels
    confidential = bool({"CONFIDENTIAL", "RESTRICTED", "CUSTOMER_DATA"} & set(labels))
    internal = "INTERNAL" in labels
    sensitive = secret or pii or confidential or internal

    if sensitive and entry["region"] not in ALLOWED_REGIONS:
        return out(DENY, "R05_REGION_NOT_ALLOWED")
    if restricted:
        return out(DENY, "R06_RESTRICTED_NEVER_LEAVES")
    if (secret or confidential) and (entry["trains_on_inputs"] or not entry["zero_data_retention"]):
        return out(DENY, "R07_CONFIDENTIAL_TO_TRAINING_OR_NON_ZDR")
    if sensitive and not entry["contract_signed"]:
        return out(DENY, "R08_NO_CONTRACT")
    if pii and entry["trains_on_inputs"]:
        return out(DENY, "R09_PII_TO_TRAINING_PROVIDER")
    if internal and entry["trains_on_inputs"]:
        return out(DENY, "R12_INTERNAL_TO_TRAINING_PROVIDER")
    if secret or pii:
        cleaned = redact(payload)
        if classify(cleaned):
            return out(DENY, "R11_RESIDUAL_AFTER_REDACTION")
        return out(REDACT, "R10_REDACT_THEN_ALLOW", cleaned)
    return out(ALLOW, "R13_ALLOW")


# ----------------------------------------------------------- evidence chain

def record_hash(rec: Dict[str, Any]) -> str:
    body = {k: v for k, v in rec.items() if k != "hash"}
    blob = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


def _pairs(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate keys")
    return dict(pairs)


def _const(name: str) -> Any:
    raise ValueError("non-finite number " + name)


def parse_json(raw: str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_const)
    except RecursionError:
        raise ValueError("nesting too deep")


def load_json(path: str) -> Any:
    with open(path, encoding="utf-8") as fh:
        return parse_json(fh.read())


def verify_bytes(data: bytes, head: Optional[str] = None) -> Tuple[bool, str, str, int]:
    """Return (ok, message, last_hash, record_count). An empty log is refused."""
    if not data:
        return False, "empty log", GENESIS, 0
    if not data.endswith(b"\n"):
        return False, "last line is not newline-terminated", GENESIS, 0
    prev, n = GENESIS, 0
    for i, line in enumerate(data.decode("utf-8", "replace").split("\n")[:-1]):
        try:
            rec = parse_json(line)
        except ValueError:
            return False, "line %d: not valid JSON" % (i + 1), prev, n
        if not isinstance(rec, dict) or tuple(sorted(rec)) != RECORD_KEYS:
            return False, "line %d: wrong record keys" % (i + 1), prev, n
        if rec["seq"] != i or isinstance(rec["seq"], bool):
            return False, "line %d: seq %r out of order" % (i + 1, rec["seq"]), prev, n
        if rec["prev"] != prev:
            return False, "line %d: prev hash does not link" % (i + 1), prev, n
        if rec["hash"] != record_hash(rec):
            return False, "line %d: record hash mismatch (tampered)" % (i + 1), prev, n
        if rec["decision"] not in DECISIONS or not isinstance(rec["rule"], str):
            return False, "line %d: bad decision or rule" % (i + 1), prev, n
        prev, n = rec["hash"], n + 1
    if head is not None and head != prev:
        return False, "head hash %s does not match last record %s" % (head, prev), prev, n
    return True, "chain ok, %d records" % n, prev, n


def append_record(log: str, today: dt.date, request: Any, result: Dict[str, Any]) -> Tuple[bool, str]:
    """Verify the existing chain, then append one linked record. Refuses on a bad chain."""
    app = request.get("app") if isinstance(request, dict) else None
    prov = request.get("provider") if isinstance(request, dict) else None
    with open(log, "a+b") as fh:
        if fcntl is not None:
            fcntl.flock(fh, fcntl.LOCK_EX)
        fh.seek(0)
        data = fh.read()
        prev, n = GENESIS, 0
        if data:
            ok, msg, prev, n = verify_bytes(data)
            if not ok:
                return False, "log chain invalid, refusing to append: " + msg
        rec: Dict[str, Any] = {
            "seq": n, "now": today.isoformat(),
            "app": app if isinstance(app, str) else None,
            "provider": prov if isinstance(prov, str) else None,
            "decision": result["decision"], "rule": result["rule"],
            "classes": result["classes"], "labels": result["labels"],
            "provider_attrs": result["provider_attrs"], "prev": prev,
        }
        rec["hash"] = record_hash(rec)
        fh.write((json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii"))
        fh.flush()
    return True, rec["hash"]


# ---------------------------------------------------------------------- CLI

def _today(arg: Optional[str]) -> dt.date:
    if arg is None:
        return dt.datetime.now(dt.timezone.utc).date()
    if not DATE_RE.match(arg):
        raise ValueError("--now must be YYYY-MM-DD")
    return dt.date.fromisoformat(arg)


def cmd_decide(args: argparse.Namespace) -> int:
    try:
        today = _today(args.now)
        request = load_json(args.request)
        registry = load_json(args.registry)
    except (OSError, ValueError) as exc:
        print("bad input: %s" % exc, file=sys.stderr)
        return 2
    result = decide(request, registry, today)
    try:
        ok, msg = append_record(args.log, today, request, result)
    except OSError as exc:
        print("REFUSED: cannot write evidence: %s" % exc, file=sys.stderr)
        return 1
    if not ok:
        print("REFUSED: " + msg, file=sys.stderr)
        return 1
    print(json.dumps({k: result[k] for k in ("decision", "rule", "classes", "redacted_payload")},
                     sort_keys=True))
    return 1 if result["decision"] == DENY else 0


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        with open(args.log, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        print("bad input: %s" % exc, file=sys.stderr)
        return 2
    ok, msg, _, _ = verify_bytes(data, args.head)
    print(("OK: " if ok else "REFUSED: ") + msg)
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="boundary.py", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("decide", help="decide one request and append an evidence record")
    d.add_argument("request")
    d.add_argument("--registry", required=True)
    d.add_argument("--log", required=True)
    d.add_argument("--now", help="override today, YYYY-MM-DD (default: UTC today)")
    d.set_defaults(fn=cmd_decide)
    v = sub.add_parser("verify", help="verify an evidence chain")
    v.add_argument("log")
    v.add_argument("--head", help="expected sha256 of the last record (detects truncation)")
    v.set_defaults(fn=cmd_verify)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
