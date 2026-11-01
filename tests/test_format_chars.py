import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import boundary, decide  # noqa: E402

# U+200B, U+200C, U+200D, U+2060, U+FEFF, and the soft hyphen U+00AD
FORMAT_CHARS = ["​", "‌", "‍", "⁠", "﻿", "­"]


def test_ssn_broken_by_format_char_is_classified():
    for ch in FORMAT_CHARS:
        text = "ssn 123-45" + ch + "-6789 end"
        assert boundary.classify(text) == {"PII_SSN": 1}, repr(ch)


def test_ssn_broken_by_format_char_is_not_a_bare_allow():
    for ch in FORMAT_CHARS:
        r = decide("ssn 123-45" + ch + "-6789 end")
        assert r["decision"] == boundary.REDACT, repr(ch)
        assert r["rule"] == "R10_REDACT_THEN_ALLOW", repr(ch)
        assert "6789" not in r["redacted_payload"], repr(ch)


def test_format_char_inside_text_label_is_still_seen():
    assert boundary.text_labels("CONFI​DENTIAL plan") == ["CONFIDENTIAL"]


def test_plain_text_is_unchanged_by_normalising():
    assert boundary.normalize("hello 123") == "hello 123"
