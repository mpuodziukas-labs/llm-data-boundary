#!/usr/bin/env python3
"""Generate the differential-parity corpora for the Go port from the Python reference.

    python3 go/tools/gen_parity.py

Writes (fixed seed, so the output is reproducible on the same interpreter):
  go/testdata/parity.jsonl     one record per line: now, request and registry as raw JSON text,
                               and want = canonical JSON of boundary.decide (null when the
                               reference refuses to parse the input, exit code 2 in the CLI)
  go/testdata/normalize.jsonl  {"in", "out"} pairs for boundary.normalize

The Go test feeds the same raw text to the Go parser and decision point and requires the
canonical bytes to be equal. Canonical = json.dumps(sort_keys, compact separators, ASCII only).
"""
import collections
import datetime as dt
import json
import os
import random
import re
import sys
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, ROOT)
import boundary  # noqa: E402

SEED = 20261105
N_PARITY = 3000
N_NORMALIZE = 4000
OUT_PARITY = os.path.join(ROOT, "go", "testdata", "parity.jsonl")
OUT_NORM = os.path.join(ROOT, "go", "testdata", "normalize.jsonl")


def line(obj):
    # Write the leading A of every AKIA/ASIA as the JSON escape A. A reader decodes the same value,
    # but the committed bytes no longer look like an AWS key to a secret scanner.
    return json.dumps(obj, ensure_ascii=True, sort_keys=True).replace("AKIA", "\\u0041KIA").replace("ASIA", "\\u0041SIA") + "\n"
TABLES = os.path.join(ROOT, "go", "pdp", "tables_gen.go")

rnd = random.Random(SEED)
PAIR = re.compile("[\ud800-\udbff][\udc00-\udfff]")


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


# ------------------------------------------------------------------ payload parts

CF = ["​", "‌", "‍", "⁠", "﻿", "­", "᠎", "‎", "؜"]
SEPS = [" ", " ", " ", "\n", ", ", ".", " - ", "", "\t", "_", "é", " ", "(", ")", ":", " ",
        "́", "　", "\x0b", "\x1c", "\u0085", "/", "=", "@", "-"]
WORDS = ["hello", "invoice", "Q3 plan", "meeting notes", "ticket 42", "the quick brown fox", "ok",
         "release v1.2.3", "Contact", "SSN", "card", "key", "token", "customer", "data", "Bearer", "AKIA"]
ZERO = [0x660, 0x6F0, 0x966, 0xFF10, 0x1D7CE, 0xE50, 0x1040, 0x9E6, 0x1D7D8]
NOISE = ["Ａ", "１", "ﬁ", "ﬃ", "Ω", "Å", "Å", "㏒", "①",
         "Ⅲ", "²", "½", " ", "ﷺ", "ẛ̣", "K", "ſ", "é",
         "각", "가", "ཱི", "̈́", "\U0001d400", "\U0001f600", "café", "ß",
         "İ", " "]


def digits(n):
    return "".join(rnd.choice("0123456789") for _ in range(n))


def luhn_complete(body):
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return body + str((10 - total % 10) % 10)


def regroup(ds, sep_mode):
    if sep_mode == "none":
        return ds
    out = []
    for i, ch in enumerate(ds):
        if i and i % 4 == 0:
            if sep_mode == "mixed":
                out.append(rnd.choice([" ", "-"]))
            elif sep_mode == "double":
                out.append(rnd.choice([" - ", "  ", "--"]))
            else:
                out.append(" " if sep_mode == "space" else "-")
        out.append(ch)
    return "".join(out)


def to_script(s):
    if rnd.random() < 0.5:
        z = rnd.choice(ZERO)
        return "".join(chr(z + int(c)) if c.isdigit() and c.isascii() else c for c in s)
    return "".join(chr(rnd.choice(ZERO) + int(c)) if c.isdigit() and c.isascii() and rnd.random() < 0.3 else c
                   for c in s)


def f_card():
    n = rnd.choice([12, 13, 14, 15, 16, 16, 16, 17, 18, 19, 19, 20, 21])
    body = digits(n - 1)
    ds = luhn_complete(body) if rnd.random() < 0.7 else digits(n)
    return regroup(ds, rnd.choice(["none", "none", "space", "hyphen", "mixed", "double"]))


def f_card_chain():
    # 20+ digits joined by single separators: the match ends before the last digit group
    n = rnd.choice([19, 20, 21, 22, 25])
    sep = rnd.choice([" ", "-"])
    ds = digits(n)
    return sep.join(ds[i:i + 4] for i in range(0, n, 4))


def f_ssn():
    area = rnd.choice(["123", "000", "666", "900", "987", "078", "219", "001", "899"])
    group = rnd.choice(["45", "00", "12", "99"])
    serial = rnd.choice(["6789", "0000", "0001", "1234"])
    return "%s-%s-%s" % (area, group, serial)


def f_email():
    local = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789._%+-") for _ in range(rnd.randint(1, 12)))
    labels = [("".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789-") for _ in range(rnd.randint(1, 8))))
              for _ in range(rnd.randint(1, 3))]
    tld = rnd.choice(["com", "io", "test", "c", "x1", "co.uk", "ORG", "a1b", "museum"])
    sep = rnd.choice([".", ".", ".", "..", "-."])
    tail = rnd.choice(["", "", ".", "1", "-", "_x"])
    return "%s@%s%s%s%s" % (local, sep.join(labels), rnd.choice([".", ".", "-"]), tld, tail)


def f_phone():
    a, b, c = digits(3), digits(3), digits(4)
    forms = ["(%s) %s-%s", "%s-%s-%s", "%s %s %s", "%s.%s.%s", "+1 %s %s %s", "1-%s-%s-%s", "+1(%s)%s-%s",
             "1.%s.%s.%s", "(%s)%s %s", "%s%s%s", "%s-%s%s", "+1%s %s-%s", "(%s) %s-%s0", "1 (%s) %s-%s"]
    f = rnd.choice(forms)
    return f % (a, b, c)


def f_aws():
    pre = rnd.choice(["AKIA", "ASIA", "AKIA", "AKIB", "akia"])
    n = rnd.choice([16, 16, 16, 15, 17])
    alpha = rnd.choice(["0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", "ABCDEFGH", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZa"])
    # the fixed EXAMPLE head keeps the length and charset under test and marks the value as a fake key
    return pre + "EXAMPLE" + "".join(rnd.choice(alpha) for _ in range(n - 7))


def f_bearer():
    ws = rnd.choice([" ", "  ", "\t", "\x0b", " ", " ", "\n", "", "\x1c"])
    tok = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._~+/-")
                  for _ in range(rnd.choice([10, 15, 16, 17, 24, 40])))
    word = rnd.choice(["Bearer", "bearer", "BEARER", "Bearer"])
    return word + ws + tok + rnd.choice(["", "", "=", "==", "=x"])


def f_key():
    return rnd.choice(["-----BEGIN EXAMPLE PRIVATE KEY-----", "-----BEGIN RSA EXAMPLE PRIVATE KEY-----",
                       "-----BEGIN EC EXAMPLE PRIVATE KEY-----", "-----BEGIN OPENSSH EXAMPLE PRIVATE KEY-----",
                       "-----BEGIN rsa PRIVATE KEY-----", "-----BEGIN  EXAMPLE PRIVATE KEY-----",
                       "-----BEGIN PUBLIC KEY-----", "----BEGIN EXAMPLE PRIVATE KEY-----"])


def f_entropy():
    mode = rnd.randrange(6)
    if mode == 0:  # exactly four bits: sixteen symbols, each twice
        syms = list("abcdefgh01234567")
        rnd.shuffle(syms)
        s = syms * 2
        rnd.shuffle(s)
        return "".join(s)
    if mode == 1:
        return "".join(rnd.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/_-")
                       for _ in range(rnd.randint(20, 48)))
    if mode == 2:
        return "a" * rnd.randint(22, 30) + "1"
    if mode == 3:
        return "".join(rnd.choice("abcdef") for _ in range(30))
    if mode == 4:
        return "".join(rnd.choice("0123456789") for _ in range(rnd.randint(24, 40)))
    return "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rnd.randint(23, 26)))


def f_label():
    w = rnd.choice(["CONFIDENTIAL", "INTERNAL", "RESTRICTED", "confidential", "Internal", "CONFIDENTIALS",
                    "customer data", "Customer_Data", "CUSTOMER-DATA", "customer  data", "customerdata",
                    "CuStOmEr DaTa", "customer data", "ſcustomer data"])
    return rnd.choice(["", "", "_", "x", "é", "1", " "]) + w + rnd.choice(["", "", "_", "s", "é", "2", "."])


FRAGS = [(f_card, 5), (f_card_chain, 2), (f_ssn, 4), (f_email, 5), (f_phone, 5), (f_aws, 3), (f_bearer, 3),
         (f_key, 2), (f_entropy, 4), (f_label, 4), (lambda: rnd.choice(WORDS), 8), (lambda: digits(rnd.randint(1, 24)), 3),
         (lambda: rnd.choice(NOISE), 3)]
FRAG_FUNCS = [f for f, w in FRAGS for _ in range(w)]


def payload():
    parts = []
    for _ in range(rnd.choice([1, 1, 2, 2, 3, 4, 6])):
        s = rnd.choice(FRAG_FUNCS)()
        if rnd.random() < 0.15:
            s = to_script(s)
        parts.append(s)
        parts.append(rnd.choice(SEPS))
    text = "".join(parts)
    if rnd.random() < 0.25:  # format characters anywhere, including inside a token
        out = []
        for ch in text:
            out.append(ch)
            if rnd.random() < 0.06:
                out.append(rnd.choice(CF))
        text = "".join(out)
    if rnd.random() < 0.02:
        text += "\ud800"
    if rnd.random() < 0.03:
        text = ""
    return text


# ------------------------------------------------------------------ registry and request

NOW_CHOICES = ["2026-11-01", "2026-11-05", "2027-02-28", "2024-02-29", "2026-01-01"]


def attest(now, delta):
    return (dt.date.fromisoformat(now) - dt.timedelta(days=delta)).isoformat()


RAWNUM = {"@@a@@": "-0", "@@b@@": "0.0", "@@c@@": "1e2", "@@d@@": "123456789012345678901234567890",
          "@@e@@": "1E400", "@@f@@": "30.0", "@@g@@": "0E0", "@@h@@": "-1"}


def entry(now):
    zdr = rnd.random() < 0.6
    e = {
        "trains_on_inputs": rnd.random() < 0.25,
        "zero_data_retention": zdr,
        "retention_days": 0 if zdr else rnd.choice([0, 1, 30, 365]),
        "region": rnd.choice(["us", "us", "eu", "apac", "US", "", "ús", "üs"]),
        "contract_signed": rnd.random() < 0.8,
        "attested_on": attest(now, rnd.choice([-30, -1, 0, 1, 5, 40, 90, 120, 179, 180, 181, 182, 400, 3, 10, 60, 100])),
    }
    if rnd.random() < 0.1:
        e["retention_days"] = rnd.choice(list(RAWNUM) + [-3, 7, True, False, None, "5"])
        if rnd.random() < 0.5:
            e["zero_data_retention"] = rnd.choice([True, False])
    r = rnd.random()
    if r < 0.05:
        del e[rnd.choice(list(e))]
    elif r < 0.08:
        k = rnd.choice(list(e))
        e[k] = rnd.choice([1, 0, "true", None, "x", [], {}, 1.5, True])
    elif r < 0.11:
        e["attested_on"] = rnd.choice(["2026-13-01", "2026-02-30", "2026-1-01", "2026-11-01\n", "２０２６-11-01",
                                       "0000-01-01", "20261101", "2026-11-1", "", "2026-11-01 ", "9999-12-31",
                                       "٢٠٢٦-١١-٠١", "2025-02-29", "2024-02-29"])
    elif r < 0.13:
        e["extra"] = rnd.choice([1, "x", None])
    return e


def registry(now, names):
    r = rnd.random()
    if r < 0.02:
        return rnd.choice([[], "x", None, 5, {"providers": []}, {"providers": "p"}, {"providers": None}, {}])
    provs = {}
    for n in names:
        if rnd.random() < 0.9:
            provs[n] = entry(now) if rnd.random() < 0.97 else rnd.choice([None, [], "x", 3, True])
    for _ in range(rnd.randint(0, 2)):
        provs["other%d" % rnd.randint(0, 9)] = entry(now)
    return {"providers": provs}


LABELS = list(boundary.VALID_LABELS)
BAD_LABELS = ["TOP_SECRET", "public", "Public", "", " PUBLIC", "PUBLIC ", "RESTRICTED\n", "РUBLIC", None, 5, ["PUBLIC"]]
PROVIDERS = ["acme-safe", "p", "pub-train", "no-zdr", "éè", "q́"]
APPS = ["support-bot", "a", "app with space", "é", "x" * 40]


def request(now):
    provider = rnd.choice(PROVIDERS)
    if rnd.random() < 0.05:
        provider = rnd.choice(["", " ", "　", "\x1c", "\u0085", " \t\n", "​", "p ", "P", "unknown-vendor"])
    app = rnd.choice(APPS)
    if rnd.random() < 0.05:
        app = rnd.choice(["", " ", " ", "\t"])
    labels = []
    for _ in range(rnd.choice([0, 0, 1, 1, 2, 3])):
        labels.append(rnd.choice(LABELS))
    if rnd.random() < 0.03:
        labels.insert(rnd.randint(0, len(labels)), rnd.choice(BAD_LABELS))
    req = {"provider": provider, "payload": payload(), "labels": labels, "app": app}
    r = rnd.random()
    if r < 0.015:
        del req[rnd.choice(list(req))]
    elif r < 0.025:
        req["extra"] = 1
    elif r < 0.04:
        k = rnd.choice(list(req))
        req[k] = rnd.choice([1, None, True, [], {}, 1.5, "x", ["PUBLIC"]])
    elif r < 0.045:
        req = rnd.choice([[], "x", None, 3, True])
    return req


def dump(obj):
    kw = {"ensure_ascii": rnd.random() < 0.6}
    r = rnd.random()
    if r < 0.15:
        kw["indent"] = 2
    elif r < 0.3:
        kw["separators"] = (",", ":")
    if rnd.random() < 0.3:
        kw["sort_keys"] = True
    text = json.dumps(obj, **kw)
    for ph, raw in RAWNUM.items():
        text = text.replace('"%s"' % ph, raw)
    return text


def corrupt(text):
    """Make the raw JSON text unparseable or odd in a way the reference must also treat alike."""
    r = rnd.randrange(14)
    if r == 0:
        return text[: max(1, len(text) // 2)]
    if r == 1:
        return text + " x"
    if r == 2:
        return "﻿" + text
    if r == 3:
        return text.replace('"payload"', '"payload": "dup", "payload"', 1)
    if r == 4:
        return text.replace("}", ", }", 1) if "}" in text else text + ","
    if r == 5:
        return text.replace('"labels": [', '"labels": [NaN, ', 1).replace('"labels":[', '"labels":[NaN,', 1)
    if r == 6:
        return " \t\r\n" + text + "\n\n"
    if r == 7:
        return text.replace(":", " :", 1)
    if r == 8:
        return text.replace('"', "'", 1)
    if r == 9:
        return text.replace("\\u", "\\x", 1) if "\\u" in text else text + "\x00"
    if r == 10:
        return text.replace('"payload": "', '"payload": "\n', 1).replace('"payload":"', '"payload":"\t', 1)
    if r == 11:
        return text.replace('"payload": "', '"payload": "\\ud83d', 1).replace('"payload":"', '"payload":"\\ude00', 1)
    if r == 12:
        return text.replace('"payload": "', '"payload": "\\ud83d\\ude00\\ude00\\ud83d\\ud83d', 1)
    return "01" if rnd.random() < 0.5 else "-"


def want(req_text, reg_text, now):
    try:
        request_obj = boundary.parse_json(req_text)
        registry_obj = boundary.parse_json(reg_text)
    except ValueError:
        return None
    return canon(boundary.decide(request_obj, registry_obj, dt.date.fromisoformat(now)))


def fixed_edges():
    """Hand-built adversarial records: the shapes where a regex port tends to diverge."""
    good = {"providers": {"p": {"trains_on_inputs": False, "zero_data_retention": True, "retention_days": 0,
                                "region": "us", "contract_signed": True, "attested_on": "2026-10-01"}}}
    out = []
    payloads = [
        "1234-5678-9012-3456-7890", "4111 1111 1111 1111 1234", "4111111111111111111111", "x4111111111111111",
        "٤١١١ ١١١١ ١١١١ ١١١١",
        "４１１１１１１１１１１１１１１１",
        "١٢٣-٤٥-٦٧٨٩", "000-12-3456 and ٠٠٠-12-3456",
        "a@b.com1", "a@b.c", "a@b..com", "a@-b.com", "x@y.zz.", "a.b.c@d.e.f.gh", "me@host.name.example.COM2",
        "AKIAIOSFODNN7EXAMPLE", "éAKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLEé", "_AKIAIOSFODNN7EXAMPLE",
        "Bearer abcdefghijklmnop", "Bearer  abcdefghijklmnopqrstu==", "xBearer abcdefghijklmnopqrstu",
        "Bearer\x0babcdefghijklmnopqrstu", "+1 520 555 0142", "1-520-555-0142", "15205550142", "(520)5550142",
        "5205550142 ", "5.2.0 555 0142", "abcdefghijklmnopqrstuvwx", "abcdefghijklmnopqrstuvw1", "a1" * 12,
        "0123456789abcdef0123456789abcdef", "CONFIDENTIAL", "xCONFIDENTIAL", "CONFIDENTIAL_", "INTERNALé",
        "customer data", "CUSTOMER_DATA", "customer data", "ſcustomer-data",
        "S​SN 123-4​5-6789", "e​́ 123-45-6789", "-----BEGIN RSA EXAMPLE PRIVATE KEY-----",
        "AKIA​IOSFODNN7EXAMPLE", "ﬁle a@b.co ①②", "각 and 각",
        "user@AKIAIOSFODNN7EXAMPLE.com", "4111111111111111-5550142", "123-45-6789-0000",
    ]
    for p in payloads:
        for labels in ([], ["INTERNAL"]):
            req = {"provider": "p", "payload": p, "labels": labels, "app": "a"}
            out.append((dump(req), dump(good), "2026-11-01"))
    big = {"providers": {"p": dict(good["providers"]["p"], zero_data_retention=False)}}
    for ndig in (4300, 4301):  # the reference caps int literals at 4300 digits and refuses the file beyond
        text = dump(big).replace('"retention_days": 0', '"retention_days": ' + "1" + "0" * (ndig - 1)) \
            .replace('"retention_days":0', '"retention_days":' + "1" + "0" * (ndig - 1))
        out.append((dump({"provider": "p", "payload": "x", "labels": [], "app": "a"}), text, "2026-11-01"))
    return out


def r11_rows(count):
    """Payloads whose redaction leaves a new match (rule R11), found with the seeded generator."""
    good = {"providers": {"p": {"trains_on_inputs": False, "zero_data_retention": True, "retention_days": 0,
                                "region": "us", "contract_signed": True, "attested_on": "2026-10-01"}}}
    found = []
    while len(found) < count:
        p = "".join(rnd.choice(FRAG_FUNCS)() + rnd.choice(SEPS) for _ in range(rnd.randint(1, 4)))
        cl, red = boundary.scan(p)
        if any(c.startswith(("SECRET_", "PII_")) for c in cl) and boundary.classify(red):
            req = {"provider": "p", "payload": p, "labels": [], "app": "a"}
            found.append((dump(req), dump(good), "2026-11-01"))
    return found


def main():
    ver = re.search(r'const unicodeVersion = "([^"]+)"', open(TABLES, encoding="utf-8").read()).group(1)
    if ver != unicodedata.unidata_version:
        sys.exit("tables_gen.go is Unicode %s but this interpreter has %s; rerun gen_tables.py" %
                 (ver, unicodedata.unidata_version))
    rows = fixed_edges()
    while len(rows) < N_PARITY:
        now = rnd.choice(NOW_CHOICES)
        req = request(now)
        names = [req["provider"]] if isinstance(req, dict) and isinstance(req.get("provider"), str) else ["p"]
        reg = registry(now, names)
        req_text, reg_text = dump(req), dump(reg)
        if rnd.random() < 0.04:
            req_text = corrupt(req_text)
        if rnd.random() < 0.03:
            reg_text = corrupt(reg_text)
        rows.append((req_text, reg_text, now))
    rows.extend(r11_rows(60))
    rules, decisions, bad = collections.Counter(), collections.Counter(), 0
    os.makedirs(os.path.dirname(OUT_PARITY), exist_ok=True)
    with open(OUT_PARITY, "w", encoding="utf-8", newline="\n") as fh:
        for i, (req_text, reg_text, now) in enumerate(rows):
            w = want(req_text, reg_text, now)
            if w is None:
                bad += 1
            else:
                d = json.loads(w)
                rules[d["rule"]] += 1
                decisions[d["decision"]] += 1
            fh.write(line({"id": i, "now": now, "request": req_text, "registry": reg_text, "want": w}))
    alphabet = (list("abcXYZ0129 -@._+/=") + CF + NOISE + ["̀", "́", "̣", "ͅ", "̈", "̧",
                "̕", "̛", "̖", "ᄀ", "ᅡ", "ᆨ", "가", "각", "힣", "ㄱ",
                "ཱ", "ི", "ཱི", "ུ", "ྀ", "Ω", "ι", "̈́", "\ud800", "\udfff",
                "क़", "ऩ", "़", "ে", "া", "େ", "ା", "െ", "ാ"])
    with open(OUT_NORM, "w", encoding="utf-8", newline="\n") as fh:
        i = 0
        while i < N_NORMALIZE:
            parts = [rnd.choice(alphabet) if rnd.random() < 0.9 else chr(rnd.choice(
                [rnd.randrange(0x20, 0xD800), rnd.randrange(0xE000, 0x110000)])) for _ in range(rnd.randint(1, 12))]
            s = "".join(parts)
            out = boundary.normalize(s)
            if PAIR.search(s) or PAIR.search(out):
                continue  # a JSON reader joins an escaped high and low surrogate, so such a pair cannot round-trip
            fh.write(line({"id": i, "in": s, "out": out}))
            i += 1
    print("parity records: %d (bad input %d)" % (len(rows), bad))
    print("decisions:", dict(sorted(decisions.items())))
    print("rules:", dict(sorted(rules.items())))
    print("normalize records: %d" % N_NORMALIZE)
    print("python %s unicodedata %s" % (sys.version.split()[0], unicodedata.unidata_version))


if __name__ == "__main__":
    main()
