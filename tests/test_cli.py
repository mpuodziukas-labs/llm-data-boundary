import contextlib
import io
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import NOW, ROOT, boundary, cli, prov, reg, req, write_json  # noqa: E402


def test_deeply_nested_json_is_bad_input_exit_2(tmp_path):
    log = os.path.join(str(tmp_path), "e.jsonl")
    rp, gp = os.path.join(str(tmp_path), "r.json"), os.path.join(str(tmp_path), "g.json")
    write_json(gp, reg(p=prov()))
    with open(rp, "w") as fh:
        fh.write("[" * 100000 + "]" * 100000)
    assert boundary.main(["decide", rp, "--registry", gp, "--log", log, "--now", NOW]) == 2
    assert not os.path.exists(log)


def test_evaluate_rejects_arguments_with_exit_two():
    r = subprocess.run([sys.executable, os.path.join(ROOT, "evaluate.py"), "--bogus"],
                       capture_output=True, text=True)
    assert r.returncode == 2
    assert "usage" in r.stderr


def test_exit_codes(tmp_path):
    p = reg(p=prov(), t=prov(trains=True, zdr=False, days=30))
    assert cli(tmp_path, req("hello", provider="p"), p) == 0
    assert cli(tmp_path, req("a@b.test", provider="p"), p) == 0  # REDACT-THEN-ALLOW
    assert cli(tmp_path, req("a@b.test", provider="t"), p) == 1


def test_bad_inputs_exit_2_and_write_no_evidence(tmp_path):
    log = os.path.join(str(tmp_path), "e.jsonl")
    rp, gp = os.path.join(str(tmp_path), "r.json"), os.path.join(str(tmp_path), "g.json")
    write_json(gp, reg(p=prov()))
    for body in ('{"provider":', '{"a":1,"a":2}', '{"a": NaN}', ""):
        with open(rp, "w") as fh:
            fh.write(body)
        assert boundary.main(["decide", rp, "--registry", gp, "--log", log, "--now", NOW]) == 2, body
    assert boundary.main(["decide", rp + ".missing", "--registry", gp, "--log", log]) == 2
    assert boundary.main(["decide", rp, "--registry", gp, "--log", log, "--now", "11/01/2026"]) == 2
    assert boundary.main(["bogus"]) == 2
    assert not os.path.exists(log)


def test_duplicate_key_registry_is_bad_input(tmp_path):
    rp, gp = os.path.join(str(tmp_path), "r.json"), os.path.join(str(tmp_path), "g.json")
    write_json(rp, req())
    with open(gp, "w") as fh:
        fh.write('{"providers": {"p": {}, "p": {}}}')
    assert boundary.main(["decide", rp, "--registry", gp, "--log", os.path.join(str(tmp_path), "e"), "--now", NOW]) == 2


def test_script_runs_as_a_process_and_is_deterministic(tmp_path):
    rp, gp = os.path.join(str(tmp_path), "r.json"), os.path.join(str(tmp_path), "g.json")
    write_json(rp, req("mail a@b.test", provider="p"))
    write_json(gp, reg(p=prov()))
    outs, logs = [], []
    for i in range(2):
        log = os.path.join(str(tmp_path), "e%d.jsonl" % i)
        r = subprocess.run([sys.executable, os.path.join(ROOT, "boundary.py"), "decide", rp, "--registry", gp,
                            "--log", log, "--now", NOW], capture_output=True, text=True)
        assert r.returncode == 0
        outs.append(r.stdout)
        with open(log, "rb") as fh:
            logs.append(fh.read())
    assert outs[0] == outs[1] and logs[0] == logs[1]
    assert json.loads(outs[0])["redacted_payload"] == "mail [REDACTED:PII_EMAIL]"
    v = subprocess.run([sys.executable, os.path.join(ROOT, "boundary.py"), "verify", log], capture_output=True, text=True)
    assert v.returncode == 0 and v.stdout.startswith("OK")


def test_stdout_never_contains_a_secret_value(tmp_path):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli(tmp_path, req("key AKIAIOSFODNN7EXAMPLE", provider="p"), reg(p=prov()))
    assert "AKIAIOSFODNN7EXAMPLE" not in buf.getvalue()
