import datetime as dt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import TODAY, boundary, decide, prov, reg, req  # noqa: E402


def rule(**kw):
    r = decide(**kw)
    return r["decision"], r["rule"]


# ---- classifier
def test_luhn_valid_card_counted_and_invalid_not():
    assert boundary.classify("4111111111111111") == {"PII_CARD": 1}
    assert boundary.classify("4111111111111112") == {}


def test_luhn_known_values():
    assert boundary.luhn_ok("4111111111111111")
    assert boundary.luhn_ok("5500005555555559")
    assert not boundary.luhn_ok("4111111111111121")


def test_ssn_invalid_ranges_not_flagged():
    for s in ("000-12-3456", "666-12-3456", "912-12-3456", "123-00-4567", "123-45-0000"):
        assert boundary.classify(s) == {}, s
    assert boundary.classify("123-45-6789") == {"PII_SSN": 1}


def test_each_class_detected():
    assert boundary.classify("a.b@example.test") == {"PII_EMAIL": 1}
    assert boundary.classify("call 520-555-0142") == {"PII_PHONE": 1}
    assert boundary.classify("AKIAIOSFODNN7EXAMPLE") == {"SECRET_AWS_KEY": 1}
    assert boundary.classify("-----BEGIN EXAMPLE PRIVATE KEY-----") == {"SECRET_PRIVATE_KEY": 1}
    assert boundary.classify("Bearer abcdEFGH1234ijklMNOP5678") == {"SECRET_BEARER": 1}


def test_entropy_flags_random_looking_and_not_plain_words():
    assert boundary.classify("q7Zk2Xv9Lm4Rt8Wn3Yb6Hc5Jd1Fg0Sa") == {"SECRET_ENTROPY": 1}
    assert boundary.classify("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1") == {}
    assert boundary.classify("internationalization-documentation-guidelines") == {}


def test_redaction_uses_typed_placeholders_and_is_clean():
    out = boundary.redact("mail a@b.test now")
    assert out == "mail [REDACTED:PII_EMAIL] now"
    assert boundary.classify(out) == {}


def test_text_labels_found_case_rules():
    assert boundary.text_labels("CONFIDENTIAL memo, customer data inside") == ["CONFIDENTIAL", "CUSTOMER_DATA"]
    assert boundary.text_labels("not confidential at all") == []


# ---- policy
def test_public_allowed():
    assert rule() == ("ALLOW", "R13_ALLOW")


def test_confidential_to_training_denied():
    assert rule(labels=["CONFIDENTIAL"], p=prov(trains=True, zdr=True)) == ("DENY", "R07_CONFIDENTIAL_TO_TRAINING_OR_NON_ZDR")


def test_confidential_to_non_zdr_denied():
    assert rule(labels=["CONFIDENTIAL"], p=prov(zdr=False, days=30)) == ("DENY", "R07_CONFIDENTIAL_TO_TRAINING_OR_NON_ZDR")


def test_confidential_to_clean_provider_allowed():
    assert rule(labels=["CONFIDENTIAL"]) == ("ALLOW", "R13_ALLOW")


def test_text_label_counts_even_when_request_says_public():
    assert rule(payload="CONFIDENTIAL plan", p=prov(trains=True)) == ("DENY", "R07_CONFIDENTIAL_TO_TRAINING_OR_NON_ZDR")
    assert "CONFIDENTIAL" in decide(payload="CONFIDENTIAL plan")["labels"]


def test_restricted_denied_even_for_clean_provider():
    assert rule(labels=["RESTRICTED"]) == ("DENY", "R06_RESTRICTED_NEVER_LEAVES")


def test_secret_to_clean_provider_redacted():
    r = decide(payload="k AKIAIOSFODNN7EXAMPLE")
    assert (r["decision"], r["rule"]) == ("REDACT-THEN-ALLOW", "R10_REDACT_THEN_ALLOW")
    assert r["redacted_payload"] == "k [REDACTED:SECRET_AWS_KEY]"
    assert "AKIA" not in r["redacted_payload"]


def test_secret_to_non_zdr_denied():
    assert rule(payload="k AKIAIOSFODNN7EXAMPLE", p=prov(zdr=False, days=7))[1] == "R07_CONFIDENTIAL_TO_TRAINING_OR_NON_ZDR"


def test_pii_to_training_denied_and_to_clean_redacted():
    assert rule(payload="a@b.test", p=prov(trains=True, zdr=False, days=30))[1] == "R09_PII_TO_TRAINING_PROVIDER"
    assert rule(payload="a@b.test")[0] == "REDACT-THEN-ALLOW"


def test_internal_rules():
    assert rule(labels=["INTERNAL"], p=prov(trains=True, zdr=False, days=30))[1] == "R12_INTERNAL_TO_TRAINING_PROVIDER"
    assert rule(labels=["INTERNAL"], p=prov(contract=False))[1] == "R08_NO_CONTRACT"
    assert rule(labels=["INTERNAL"], p=prov(region="apac"))[1] == "R05_REGION_NOT_ALLOWED"
    assert rule(labels=["PUBLIC"], p=prov(contract=False, region="apac"))[1] == "R13_ALLOW"


def test_unknown_provider_denied():
    r = boundary.decide(req(provider="ghost"), reg(p=prov()), TODAY)
    assert (r["decision"], r["rule"]) == ("DENY", "R02_UNKNOWN_PROVIDER")


def test_registry_shapes_fail_closed():
    for bad in (None, [], {"providers": []}, {"providers": None}, "x"):
        assert boundary.decide(req(), bad, TODAY)["rule"] == "R03_REGISTRY_INVALID"


def test_attestation_boundary_and_future():
    d180 = (TODAY - dt.timedelta(days=180)).isoformat()
    d181 = (TODAY - dt.timedelta(days=181)).isoformat()
    dfut = (TODAY + dt.timedelta(days=1)).isoformat()
    assert rule(p=prov(att=d180)) == ("ALLOW", "R13_ALLOW")
    assert rule(p=prov(att=d181)) == ("DENY", "R04_ATTESTATION_STALE")
    assert rule(p=prov(att=dfut)) == ("DENY", "R04_ATTESTATION_FUTURE")
    assert rule(p=prov(att=TODAY.isoformat())) == ("ALLOW", "R13_ALLOW")


def test_stale_attestation_denies_even_public_data():
    assert rule(p=prov(att="2020-01-01")) == ("DENY", "R04_ATTESTATION_STALE")


def test_every_missing_field_denied():
    for field in ("trains_on_inputs", "zero_data_retention", "retention_days", "region",
                  "contract_signed", "attested_on"):
        p = {k: v for k, v in prov().items() if k != field}
        assert rule(p=p) == ("DENY", "R03_REGISTRY_INVALID"), field


def test_wrong_types_and_bad_dates_denied():
    for patch in ({"trains_on_inputs": "false"}, {"retention_days": True}, {"retention_days": -1},
                  {"retention_days": 1.5}, {"region": 5}, {"attested_on": "2026-13-40"},
                  {"attested_on": "20260901"}, {"contract_signed": 1}):
        p = prov()
        p.update(patch)
        assert rule(p=p) == ("DENY", "R03_REGISTRY_INVALID"), patch


def test_boolean_retention_days_rejected_by_type_not_by_side_effect():
    # zdr False so the zdr/retention contradiction rule cannot catch it; only the type check can
    assert rule(p=prov(zdr=False, days=True)) == ("DENY", "R03_REGISTRY_INVALID")
    assert rule(p=prov(zdr=False, days=False)) == ("DENY", "R03_REGISTRY_INVALID")


def test_zdr_contradicting_retention_denied():
    assert rule(p=prov(zdr=True, days=30)) == ("DENY", "R03_REGISTRY_INVALID")


def test_malformed_requests_denied_not_crashed():
    bad = [None, [], "x", {}, {"provider": "p", "payload": "x", "labels": [], "app": "a", "z": 1},
           {"provider": "p", "payload": 5, "labels": [], "app": "a"},
           {"provider": "p", "payload": "x", "labels": "CONFIDENTIAL", "app": "a"},
           {"provider": "p", "payload": "x", "labels": ["SECRET-ISH"], "app": "a"},
           {"provider": "", "payload": "x", "labels": [], "app": "a"},
           {"provider": "p", "payload": "x", "labels": [], "app": "  "}]
    for b in bad:
        r = boundary.decide(b, reg(p=prov()), TODAY)
        assert (r["decision"], r["rule"]) == ("DENY", "R01_MALFORMED_REQUEST"), b


def test_residual_after_redaction_denied(monkeypatch):
    monkeypatch.setattr(boundary, "redact", lambda text: text)  # a redactor that fails to remove
    r = decide(payload="a@b.test")
    assert (r["decision"], r["rule"]) == ("DENY", "R11_RESIDUAL_AFTER_REDACTION")
    assert r["redacted_payload"] is None


def test_evidence_fields_carry_counts_never_values():
    r = decide(payload="a@b.test and c@d.test")
    assert r["classes"] == {"PII_EMAIL": 2}
    assert "a@b.test" not in repr({k: v for k, v in r.items() if k != "redacted_payload"})
    assert r["provider_attrs"]["region"] == "us"
