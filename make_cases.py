#!/usr/bin/env python3
"""Write the fixtures in cases/ once. Refuses to overwrite. All data is synthetic."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "cases")
NOW = "2026-11-01"


def prov(trains=False, zdr=True, days=0, region="us", contract=True, att="2026-09-01"):
    return {"trains_on_inputs": trains, "zero_data_retention": zdr, "retention_days": days,
            "region": region, "contract_signed": contract, "attested_on": att}


def registry():
    broken = prov()
    del broken["region"]
    return {"providers": {
        "acme-safe": prov(),
        "pub-train": prov(trains=True, zdr=False, days=30),
        "no-zdr": prov(zdr=False, days=30),
        "stale-co": prov(att="2026-03-01"),
        "edge-180": prov(att="2026-05-05"),
        "edge-181": prov(att="2026-05-04"),
        "future-co": prov(att="2026-12-01"),
        "far-region": prov(region="apac"),
        "no-contract": prov(contract=False),
        "broken-entry": broken,
        "liar-zdr": prov(zdr=True, days=30),
    }}


def req(provider, payload, labels=("PUBLIC",), app="support-bot"):
    return {"provider": provider, "payload": payload, "labels": list(labels), "app": app}


# name: (request, expected)  expected = exit, decision, rule, classes, optional redacted
C = {}
C["public_allow"] = (req("acme-safe", "The quarterly weather is sunny."),
                     dict(exit=0, decision="ALLOW", rule="R13_ALLOW", classes={}))
C["confidential_to_training_deny"] = (req("pub-train", "Roadmap draft", ["CONFIDENTIAL"]),
                                      dict(exit=1, decision="DENY", rule="R07_CONFIDENTIAL_TO_TRAINING_OR_NON_ZDR", classes={}))
C["confidential_to_non_zdr_deny"] = (req("no-zdr", "Roadmap draft", ["CONFIDENTIAL"]),
                                     dict(exit=1, decision="DENY", rule="R07_CONFIDENTIAL_TO_TRAINING_OR_NON_ZDR", classes={}))
C["confidential_to_zdr_allow"] = (req("acme-safe", "Roadmap draft", ["CONFIDENTIAL"]),
                                  dict(exit=0, decision="ALLOW", rule="R13_ALLOW", classes={}))
C["restricted_never_leaves"] = (req("acme-safe", "Board minutes", ["RESTRICTED"]),
                                dict(exit=1, decision="DENY", rule="R06_RESTRICTED_NEVER_LEAVES", classes={}))
C["aws_key_to_training_deny"] = (req("pub-train", "debug with AKIAIOSFODNN7EXAMPLE please"),
                                 dict(exit=1, decision="DENY", rule="R07_CONFIDENTIAL_TO_TRAINING_OR_NON_ZDR",
                                      classes={"SECRET_AWS_KEY": 1}))
C["secrets_redacted_for_zdr"] = (
    req("acme-safe", "-----BEGIN EXAMPLE PRIVATE KEY----- and Authorization: Bearer abcdEFGH1234ijklMNOP5678"),
    dict(exit=0, decision="REDACT-THEN-ALLOW", rule="R10_REDACT_THEN_ALLOW",
         classes={"SECRET_BEARER": 1, "SECRET_PRIVATE_KEY": 1},
         redacted_payload="[REDACTED:SECRET_PRIVATE_KEY] and Authorization: [REDACTED:SECRET_BEARER]"))
C["pii_redacted"] = (
    req("acme-safe", "Contact jane.doe@example.test or (520) 555-0142, SSN 123-45-6789, card 4111 1111 1111 1111."),
    dict(exit=0, decision="REDACT-THEN-ALLOW", rule="R10_REDACT_THEN_ALLOW",
         classes={"PII_CARD": 1, "PII_EMAIL": 1, "PII_PHONE": 1, "PII_SSN": 1},
         redacted_payload="Contact [REDACTED:PII_EMAIL] or [REDACTED:PII_PHONE], SSN [REDACTED:PII_SSN], card [REDACTED:PII_CARD]."))
C["pii_to_training_deny"] = (req("pub-train", "mail jane.doe@example.test"),
                             dict(exit=1, decision="DENY", rule="R09_PII_TO_TRAINING_PROVIDER", classes={"PII_EMAIL": 1}))
C["card_fails_luhn_allow"] = (req("acme-safe", "ref 4111111111111112 attached"),
                              dict(exit=0, decision="ALLOW", rule="R13_ALLOW", classes={}))
C["ssn_invalid_area_allow"] = (req("acme-safe", "ticket 000-12-3456 closed"),
                               dict(exit=0, decision="ALLOW", rule="R13_ALLOW", classes={}))
C["ssn_zero_width_redacted"] = (
    req("acme-safe", "SSN 123-45​-6789 on file"),
    dict(exit=0, decision="REDACT-THEN-ALLOW", rule="R10_REDACT_THEN_ALLOW", classes={"PII_SSN": 1},
         redacted_payload="SSN [REDACTED:PII_SSN] on file"))
C["entropy_secret_redacted"] = (
    req("acme-safe", "token q7Zk2Xv9Lm4Rt8Wn3Yb6Hc5Jd1Fg0Sa end"),
    dict(exit=0, decision="REDACT-THEN-ALLOW", rule="R10_REDACT_THEN_ALLOW", classes={"SECRET_ENTROPY": 1},
         redacted_payload="token [REDACTED:SECRET_ENTROPY] end"))
C["text_label_overrides_request"] = (req("pub-train", "CONFIDENTIAL: pricing sheet", ["PUBLIC"]),
                                     dict(exit=1, decision="DENY", rule="R07_CONFIDENTIAL_TO_TRAINING_OR_NON_ZDR", classes={}))
C["customer_data_in_text"] = (req("no-zdr", "Customer data export for tenant 7"),
                              dict(exit=1, decision="DENY", rule="R07_CONFIDENTIAL_TO_TRAINING_OR_NON_ZDR", classes={}))
C["internal_to_training_deny"] = (req("pub-train", "team offsite notes", ["INTERNAL"]),
                                  dict(exit=1, decision="DENY", rule="R12_INTERNAL_TO_TRAINING_PROVIDER", classes={}))
C["no_contract_deny"] = (req("no-contract", "team offsite notes", ["INTERNAL"]),
                         dict(exit=1, decision="DENY", rule="R08_NO_CONTRACT", classes={}))
C["region_not_allowed_deny"] = (req("far-region", "team offsite notes", ["INTERNAL"]),
                                dict(exit=1, decision="DENY", rule="R05_REGION_NOT_ALLOWED", classes={}))
C["unknown_provider_deny"] = (req("nobody-llc", "hello"),
                              dict(exit=1, decision="DENY", rule="R02_UNKNOWN_PROVIDER", classes={}))
C["stale_attestation_deny"] = (req("stale-co", "hello"),
                               dict(exit=1, decision="DENY", rule="R04_ATTESTATION_STALE", classes={}))
C["attestation_exactly_180_days_allow"] = (req("edge-180", "hello"),
                                           dict(exit=0, decision="ALLOW", rule="R13_ALLOW", classes={}))
C["attestation_181_days_deny"] = (req("edge-181", "hello"),
                                  dict(exit=1, decision="DENY", rule="R04_ATTESTATION_STALE", classes={}))
C["attestation_in_future_deny"] = (req("future-co", "hello"),
                                   dict(exit=1, decision="DENY", rule="R04_ATTESTATION_FUTURE", classes={}))
C["registry_field_missing_deny"] = (req("broken-entry", "hello"),
                                    dict(exit=1, decision="DENY", rule="R03_REGISTRY_INVALID", classes={}))
C["zdr_contradicts_retention_deny"] = (req("liar-zdr", "hello"),
                                       dict(exit=1, decision="DENY", rule="R03_REGISTRY_INVALID", classes={}))
C["malformed_labels_deny"] = ({"provider": "acme-safe", "payload": "hi", "labels": "CONFIDENTIAL", "app": "x"},
                              dict(exit=1, decision="DENY", rule="R01_MALFORMED_REQUEST", classes={}))
C["extra_key_deny"] = ({"provider": "acme-safe", "payload": "hi", "labels": [], "app": "x", "admin": True},
                       dict(exit=1, decision="DENY", rule="R01_MALFORMED_REQUEST", classes={}))


def main() -> int:
    if os.path.isdir(CASES) and any(os.scandir(CASES)):
        print("cases/ already populated; refusing to overwrite")
        return 1
    reg = registry()
    for name, (request, exp) in sorted(C.items()):
        d = os.path.join(CASES, name)
        os.makedirs(d)
        exp = dict(exp, now=NOW)
        for fname, obj in (("request.json", request), ("registry.json", reg), ("expected.json", exp)):
            with open(os.path.join(d, fname), "w", encoding="utf-8") as fh:
                json.dump(obj, fh, indent=2, sort_keys=True)
                fh.write("\n")
    d = os.path.join(CASES, "unparseable_request_exit2")
    os.makedirs(d)
    with open(os.path.join(d, "request.json"), "w", encoding="utf-8") as fh:
        fh.write('{"provider": "acme-safe", "payload": ')
    with open(os.path.join(d, "registry.json"), "w", encoding="utf-8") as fh:
        json.dump(reg, fh, indent=2, sort_keys=True)
        fh.write("\n")
    with open(os.path.join(d, "expected.json"), "w", encoding="utf-8") as fh:
        json.dump({"now": NOW, "exit": 2, "decision": None, "rule": None, "classes": {}}, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print("wrote %d cases" % (len(C) + 1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
