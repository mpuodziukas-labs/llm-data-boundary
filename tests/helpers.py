"""Shared helpers. Paths resolve from this file, so a copy of the repo tests itself."""
import datetime as dt
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import boundary  # noqa: E402

TODAY = dt.date(2026, 11, 1)
NOW = "2026-11-01"


def prov(trains=False, zdr=True, days=0, region="us", contract=True, att="2026-09-01"):
    return {"trains_on_inputs": trains, "zero_data_retention": zdr, "retention_days": days,
            "region": region, "contract_signed": contract, "attested_on": att}


def reg(**providers):
    return {"providers": providers}


def req(payload="hello", labels=("PUBLIC",), provider="p", app="app"):
    return {"provider": provider, "payload": payload, "labels": list(labels), "app": app}


def decide(payload="hello", labels=("PUBLIC",), p=None):
    return boundary.decide(req(payload, labels), reg(p=p or prov()), TODAY)


def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)


def cli(tmp, request, registry, log=None, now=NOW):
    """Run `decide` through main(); return exit code."""
    rp, gp = os.path.join(str(tmp), "req.json"), os.path.join(str(tmp), "reg.json")
    write_json(rp, request)
    write_json(gp, registry)
    return boundary.main(["decide", rp, "--registry", gp, "--log", log or os.path.join(str(tmp), "ev.jsonl"),
                          "--now", now])


def make_log(tmp, n=3):
    log = os.path.join(str(tmp), "ev.jsonl")
    for i in range(n):
        payload = ["hello", "mail a@b.test", "CONFIDENTIAL doc"][i % 3]
        cli(tmp, req(payload, provider="p"), reg(p=prov(trains=(i % 3 == 2))), log)
    return log


def read_records(log):
    with open(log, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh.read().splitlines()]


def write_records(log, recs, rehash=True):
    with open(log, "w", encoding="utf-8") as fh:
        for r in recs:
            if rehash:
                r["hash"] = boundary.record_hash(r)
            fh.write(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n")


def verify_ok(log):
    with open(log, "rb") as fh:
        return boundary.verify_bytes(fh.read())[0]
