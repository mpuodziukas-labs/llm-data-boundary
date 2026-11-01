import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import (boundary, cli, make_log, prov, read_records, reg, req,  # noqa: E402
                     verify_ok, write_records)


def raw(log):
    with open(log, "rb") as fh:
        return fh.read()


def test_clean_chain_verifies_and_links(tmp_path):
    log = make_log(tmp_path)
    recs = read_records(log)
    assert [r["seq"] for r in recs] == [0, 1, 2]
    assert recs[0]["prev"] == "0" * 64
    assert recs[1]["prev"] == recs[0]["hash"]
    assert boundary.main(["verify", log]) == 0


def test_records_hold_counts_not_values(tmp_path):
    log = make_log(tmp_path)
    assert "a@b.test" not in raw(log).decode()
    assert read_records(log)[1]["classes"] == {"PII_EMAIL": 1}


def test_edited_decision_refused(tmp_path):
    log = make_log(tmp_path)
    recs = read_records(log)
    recs[2]["decision"] = "ALLOW"
    write_records(log, recs, rehash=False)
    assert boundary.main(["verify", log]) == 1


def test_reordered_chain_refused(tmp_path):
    log = make_log(tmp_path)
    recs = read_records(log)
    recs[0], recs[1] = recs[1], recs[0]
    write_records(log, recs, rehash=False)
    assert boundary.main(["verify", log]) == 1


def test_first_record_dropped_refused(tmp_path):
    log = make_log(tmp_path)
    write_records(log, read_records(log)[1:], rehash=False)
    assert boundary.main(["verify", log]) == 1


def test_forged_record_with_wrong_prev_refused_even_if_rehashed(tmp_path):
    log = make_log(tmp_path)
    recs = read_records(log)
    recs[1]["prev"] = "f" * 64
    write_records(log, recs)  # hashes recomputed, so only the link is wrong
    ok, msg, _, _ = boundary.verify_bytes(raw(log))
    assert not ok and "prev" in msg


def test_forged_record_with_wrong_seq_refused_even_if_rehashed(tmp_path):
    log = make_log(tmp_path)
    recs = read_records(log)
    recs[1]["seq"] = 7
    write_records(log, recs)
    ok, msg, _, _ = boundary.verify_bytes(raw(log))
    assert not ok and "seq" in msg


def test_edit_without_rehash_refused(tmp_path):
    log = make_log(tmp_path)
    recs = read_records(log)
    recs[1]["rule"] = "R13_ALLOW"
    write_records(log, recs, rehash=False)
    ok, msg, _, _ = boundary.verify_bytes(raw(log))
    assert not ok and "tampered" in msg


def test_truncation_caught_only_with_head(tmp_path):
    log = make_log(tmp_path)
    head = read_records(log)[-1]["hash"]
    write_records(log, read_records(log)[:2], rehash=False)
    assert boundary.main(["verify", log]) == 0  # a shorter valid prefix is still a valid chain
    assert boundary.main(["verify", log, "--head", head]) == 1


def test_head_match_passes(tmp_path):
    log = make_log(tmp_path)
    head = read_records(log)[-1]["hash"]
    assert boundary.main(["verify", log, "--head", head]) == 0


def test_empty_garbage_and_unterminated_logs_refused(tmp_path):
    log = os.path.join(str(tmp_path), "x.jsonl")
    for blob in (b"", b"not json\n", b"{}\n", b'{"a":1}'):
        with open(log, "wb") as fh:
            fh.write(blob)
        assert boundary.main(["verify", log]) == 1, blob


def test_missing_log_is_bad_input(tmp_path):
    assert boundary.main(["verify", os.path.join(str(tmp_path), "none.jsonl")]) == 2


def test_decide_refuses_to_append_to_tampered_log(tmp_path):
    log = make_log(tmp_path)
    recs = read_records(log)
    recs[0]["decision"] = "DENY" if recs[0]["decision"] != "DENY" else "ALLOW"
    write_records(log, recs, rehash=False)
    before = raw(log)
    assert cli(tmp_path, req("hello", provider="p"), reg(p=prov()), log) == 1
    assert raw(log) == before


def test_decide_grows_chain_and_stays_valid(tmp_path):
    log = make_log(tmp_path, 2)
    cli(tmp_path, req("x", provider="p"), reg(p=prov()), log)
    assert verify_ok(log) and len(read_records(log)) == 3


def test_malformed_request_still_leaves_evidence(tmp_path):
    log = os.path.join(str(tmp_path), "e.jsonl")
    assert cli(tmp_path, {"provider": "p"}, reg(p=prov()), log) == 1
    rec = read_records(log)[0]
    assert rec["rule"] == "R01_MALFORMED_REQUEST" and rec["app"] is None


def test_unwritable_log_means_no_allow(tmp_path):
    bad = os.path.join(str(tmp_path), "no_such_dir", "ev.jsonl")
    assert cli(tmp_path, req("hello", provider="p"), reg(p=prov()), bad) == 1
