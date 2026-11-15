"""Keeps docs/PRIVACY-MAPPING.md honest: every name in an evidence cell must exist."""
import os
import re

from helpers import ROOT

DOC = os.path.join(ROOT, "docs", "PRIVACY-MAPPING.md")
TESTS = os.path.join(ROOT, "tests")
CASES = os.path.join(ROOT, "cases")


def rows():
    with open(DOC, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    return [[c.strip() for c in l.strip().strip("|").split("|")]
            for l in lines if l.startswith("| GDPR") or l.startswith("| CCPA")]


def defined_tests():
    found = set()
    for fn in os.listdir(TESTS):
        if fn.startswith("test_") and fn.endswith(".py") and fn != "test_privacy_mapping.py":
            with open(os.path.join(TESTS, fn), encoding="utf-8") as fh:
                found |= set(re.findall(r"^def (test_\w+)\(", fh.read(), re.M))
    return found


def test_table_has_nine_rows_and_every_row_has_evidence():
    table = rows()
    assert len(table) == 9
    for cells in table:
        assert len(cells) == 5, cells
        assert re.findall(r"`([^`]+)`", cells[4]), cells


def test_every_evidence_name_exists():
    tests, missing = defined_tests(), []
    for cells in rows():
        for name in re.findall(r"`([^`]+)`", cells[4]):
            ok = name in tests if name.startswith("test_") else os.path.isdir(os.path.join(CASES, name))
            if not ok:
                missing.append(name)
    assert not missing, missing
