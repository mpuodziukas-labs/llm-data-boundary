#!/usr/bin/env python3
"""Mutation check. Each mutant changes one spot in boundary.py inside a throwaway copy of the
repo (a temporary directory, removed by the interpreter when the run ends). The pytest suite
then runs on the copy. A mutant is killed when the suite exits non-zero."""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
B = "boundary.py"

MUTANTS = [
    ("stale_boundary_off_by_one", "if age > MAX_ATTEST_AGE_DAYS:", "if age >= MAX_ATTEST_AGE_DAYS:"),
    ("stale_attestation_ignored", "if age > MAX_ATTEST_AGE_DAYS:", "if False:"),
    ("future_attestation_accepted", "if age < 0:", "if False:"),
    ("zdr_requirement_dropped", 'entry["trains_on_inputs"] or not entry["zero_data_retention"]', 'entry["trains_on_inputs"]'),
    ("training_flag_ignored", 'entry["trains_on_inputs"] or not entry["zero_data_retention"]', 'not entry["zero_data_retention"]'),
    ("luhn_check_skipped", "return 13 <= len(digits) <= 19 and luhn_ok(digits)", "return 13 <= len(digits) <= 19"),
    ("luhn_wrong_parity", "if i % 2 == 1:", "if i % 2 == 0:"),
    ("residual_rescan_skipped", "if classify(cleaned):", "if False:"),
    ("chain_prev_link_unchecked", 'if rec["prev"] != prev:', "if False:"),
    ("chain_hash_unchecked", 'if rec["hash"] != record_hash(rec):', "if False:"),
    ("chain_seq_unchecked", 'if rec["seq"] != i or isinstance(rec["seq"], bool):', "if False:"),
    ("append_to_tampered_log", '            if not ok:\n                return False, "log chain invalid', '            if False:\n                return False, "log chain invalid'),
    ("restricted_label_allowed", "if restricted:", "if False:"),
    ("contract_ignored", 'if sensitive and not entry["contract_signed"]:', "if False:"),
    ("region_ignored", 'if sensitive and entry["region"] not in ALLOWED_REGIONS:', "if False:"),
    ("malformed_request_not_denied", "    if err:\n        return _result(DENY", "    if False:\n        return _result(DENY"),
    ("deny_exits_zero", 'return 1 if result["decision"] == DENY else 0', "return 0"),
    ("entropy_threshold_zero", "ENTROPY_THRESHOLD = 4.0", "ENTROPY_THRESHOLD = 0.0"),
    ("ssn_area_rules_dropped", 'if area in ("000", "666") or area.startswith("9"):', "if False:"),
    ("empty_log_verifies", 'return False, "empty log", GENESIS, 0', 'return True, "empty log", GENESIS, 0'),
    ("head_hash_unchecked", "if head is not None and head != prev:", "if False:"),
    ("zdr_retention_contradiction_ignored", 'if entry["zero_data_retention"] and entry["retention_days"] != 0:', "if False:"),
    ("bool_accepted_as_int", "if isinstance(v, bool) != (typ is bool):", "if False:"),
    ("unknown_provider_rule_lost", "if entry is None:", "if False:"),
    ("text_labels_ignored", 'labels = sorted(set(request["labels"]) | set(text_labels(payload)))', 'labels = sorted(set(request["labels"]))'),
    ("placeholder_untyped", 'return "[REDACTED:%s]" % cls', 'return "[REDACTED]"'),
    ("duplicate_keys_accepted", "if len(keys) != len(set(keys)):", "if False:"),
    ("format_char_strip_removed", 'return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")', "return text"),
    ("evidence_write_failure_allows", 'print("REFUSED: cannot write evidence: %s" % exc, file=sys.stderr)\n        return 1', 'print("REFUSED: cannot write evidence: %s" % exc, file=sys.stderr)\n        return 0'),
]


def run_suite(root):
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-x"],
                       cwd=root, capture_output=True, text=True)
    return r.returncode


def main():
    with open(os.path.join(HERE, B), encoding="utf-8") as fh:
        source = fh.read()
    if run_suite(HERE) != 0:
        print("control: suite fails unmodified")
        return 1
    print("control: suite passes unmodified")
    killed = 0
    for name, old, new in MUTANTS:
        if source.count(old) != 1:
            print("INVALID %s (spot found %d times)" % (name, source.count(old)))
            continue
        mutated = source.replace(old, new)
        try:
            compile(mutated, B, "exec")
        except SyntaxError:
            print("INVALID %s (does not compile)" % name)
            continue
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "repo")
            shutil.copytree(HERE, root, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
            with open(os.path.join(root, B), "w", encoding="utf-8") as fh:
                fh.write(mutated)
            dead = run_suite(root) != 0
        killed += dead
        print("%s %s" % ("KILLED  " if dead else "SURVIVED", name))
    print("mutants: %d/%d killed" % (killed, len(MUTANTS)))
    return 0 if killed == len(MUTANTS) else 1


if __name__ == "__main__":
    sys.exit(main())
