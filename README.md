# llm-data-boundary

[![CI](https://github.com/mpuodziukas-labs/llm-data-boundary/actions/workflows/ci.yml/badge.svg)](https://github.com/mpuodziukas-labs/llm-data-boundary/actions/workflows/ci.yml)

Proves: a policy-as-code gate that decides, per request, whether text may go to a given LLM provider (ALLOW, REDACT-THEN-ALLOW or DENY), using the provider's recorded attributes (trains on inputs, zero data retention, region, contract, attestation date), and writes a hash-chained evidence record for every decision that a verifier refuses if it is edited, reordered or forged. Verify in 60s: `python3 evaluate.py`

All data here is synthetic. Engineering evidence, not legal advice, no certification claimed.

## The problem

"Confidential data never trains a public model" is usually a sentence in a policy document. Nothing checks it per request, and nothing records why a given request was let through. Provider facts also go stale: a vendor that was zero-retention a year ago may not be today.

This repository makes the sentence executable. A request (provider id, payload, labels, app) is classified, checked against a provider registry, and decided by an ordered rule list. The first matching rule wins and its id is written to an append-only log. Anything unknown, stale, contradictory or malformed is DENY.

## Run it (60s)

Standard library Python 3 only (3.9 or later). No network. No install.

```
python3 evaluate.py
python3 boundary.py decide cases/pii_redacted/request.json --registry cases/pii_redacted/registry.json --log /tmp/evidence.jsonl --now 2026-11-01
python3 boundary.py verify /tmp/evidence.jsonl
```

`evaluate.py` runs `boundary.py decide` over every folder in `cases/`, checks the decision, rule id, class counts, redacted text and exit code against `expected.json`, and verifies the evidence chain each run wrote. The last line is `cases: 28/28 match`.

The whole proof is `bash run.sh`: the case table, the pytest suite and the mutation check. As run by the oracle runner:

```
evaluate.py | rc=0 | cases: 28/28 match
-m pytest | rc=0 | 53 passed
mutants.py | rc=0 | mutants: 29/29 killed
```

Exit codes: `decide` returns 0 for ALLOW and REDACT-THEN-ALLOW, 1 for DENY or when it refuses (evidence cannot be written, or the existing chain is invalid), 2 for bad input (missing file, not JSON, duplicate keys, NaN, bad `--now`). `verify` returns 0 for a valid chain, 1 for a refused chain, 2 for an unreadable file.

## What it checks

Inputs. A request is `{"provider", "payload", "labels", "app"}` with exactly those keys. Labels are PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED, CUSTOMER_DATA. The registry is `{"providers": {id: {trains_on_inputs, zero_data_retention, retention_days, region, contract_signed, attested_on}}}`.

Classifier (`boundary.py`, synthetic test strings only):
- PII: email, phone, SSN-shaped (invalid ranges such as 000, 666, 9xx are not flagged), card numbers (only when the Luhn check passes).
- Secrets: AWS-key-shaped, private key headers, bearer tokens, long high-entropy strings.
- Labels: the request labels plus CONFIDENTIAL, INTERNAL, RESTRICTED or "customer data" found in the text itself, so a request cannot under-label its own payload.

Policy, first match wins:

| rule | outcome |
|---|---|
| R01 | malformed request: DENY |
| R02 | unknown provider: DENY |
| R03 | registry missing, wrong type, bad date, or `zero_data_retention` contradicting `retention_days`: DENY |
| R04 | attestation older than 180 days (exactly 180 is fresh) or dated in the future: DENY, even for public data |
| R05 | non-public data to a region outside `us`, `eu`: DENY |
| R06 | RESTRICTED label: DENY for every provider |
| R07 | secret or confidential data to a provider that trains on inputs or lacks zero data retention: DENY |
| R08 | non-public data and no signed contract: DENY |
| R09, R12 | PII or INTERNAL data to a provider that trains on inputs: DENY |
| R10, R11 | secrets or PII to an acceptable provider: replace each match with `[REDACTED:CLASS]`, scan again; a residual hit is DENY, otherwise REDACT-THEN-ALLOW |
| R13 | otherwise ALLOW |

Evidence. Every decision, including DENY, appends one JSON line: sequence number, date, app, provider, decision, rule id, class counts (never values), labels, the provider attributes used, the previous record's hash and its own sha256. `verify` refuses an empty log, a bad line, a wrong sequence number, a broken link, an edited record, and, when given `--head`, a truncated log. `decide` verifies the chain before appending and refuses to extend a bad one.

What the planted cases prove (28 folders in `cases/`):

| group | cases |
|---|---|
| allow paths | public_allow, confidential_to_zdr_allow, card_fails_luhn_allow, ssn_invalid_area_allow, attestation_exactly_180_days_allow |
| redaction | pii_redacted, secrets_redacted_for_zdr, entropy_secret_redacted, ssn_zero_width_redacted |
| deny on data class | confidential_to_training_deny, confidential_to_non_zdr_deny, restricted_never_leaves, aws_key_to_training_deny, pii_to_training_deny, internal_to_training_deny, text_label_overrides_request, customer_data_in_text |
| deny on provider facts | no_contract_deny, region_not_allowed_deny, unknown_provider_deny, stale_attestation_deny, attestation_181_days_deny, attestation_in_future_deny, registry_field_missing_deny, zdr_contradicts_retention_deny |
| malformed input | malformed_labels_deny, extra_key_deny (DENY with evidence), unparseable_request_exit2 (exit 2, no evidence) |

`tests/` holds the chain attacks (edit, reorder, drop the first record, forged record with a recomputed hash, truncation) and the CLI exit codes. `mutants.py` makes 29 one-line changes to `boundary.py` (for example: skip the staleness check, move its boundary by one day, skip the Luhn check, skip the re-scan after redaction, stop checking the previous-hash link) and requires the suite to fail on every one. The last line is `mutants: 29/29 killed`.

## Mapping

These are the author's reading of how each check supports the cited text, not an auditor's opinion. Quotes and URLs are in `SOURCES.md`.

| item | what in this repo supports it |
|---|---|
| OWASP LLM02:2025 Sensitive Information Disclosure | classifier plus R06 to R12: sensitive input is sanitized or denied before it leaves |
| OWASP LLM03:2025 Supply Chain | provider registry with attestation age and training/retention facts; R04, R07, R08 |
| NIST AI RMF MEASURE 2.10 (privacy risk examined and documented) | per-decision evidence records with class counts and the rule that fired |
| NIST AI RMF GOVERN 6.1 (third-party risk) | R02 to R05, R08: unknown, stale or uncontracted providers are denied |
| NIST AI RMF GOVERN 1.1 (legal and regulatory requirements documented) | the rule table and the evidence log are the documentation |
| EU AI Act Article 10 (data governance) | cited by article number only; primary text was not fetched in this repo |
| ISO/IEC 42001 | clause not verified from public text; no control is claimed |

## Go implementation

`go/` holds a second implementation of the decision point (allow, redact, deny) in Go, standard library only. Package `pdp` exposes `Decide`; `go/cmd/pdp` reads one JSON request on stdin and prints one JSON decision. It is the decision point only and keeps no evidence log.

What parity proves: for every request in the committed corpus, the Go decision, rule, classes, labels, attributes and redacted payload are byte-identical to what `boundary.py` returns, compared as canonical JSON (sorted keys, compact separators, ASCII escapes). The corpus is `go/testdata/parity.jsonl`, written by `go/tools/gen_parity.py` from a fixed seed, so it can be regenerated and diffed. It covers all 14 rules, including rejected input. A second corpus, `go/testdata/normalize.jsonl`, checks the Unicode normalization step on its own. Python's regex and normalization behavior is reimplemented by hand (Unicode digits, spaces and word boundaries, lookaround, backtracking, NFKC from generated tables, and `json.loads` rules such as duplicate keys and the 4300-digit integer limit). Parity shows the two agree on those inputs. It does not show they agree on inputs outside the corpus.

```
cd go && go vet ./... && go test ./... -count=1
cd go && go test ./pdp -run '^$' -fuzz FuzzDecide -fuzztime=30s
bash scripts/verify-go.sh
bash scripts/verify-go.sh --selftest
```

Counts at the time of writing: 28/28 case folders (read in place, also run through the built CLI), 3060/3060 parity records, 4000/4000 normalization records, and a 30 second fuzz run with no panic, deterministic output, and denial of any unknown data class. `verify-go.sh` fails if the parity corpus has fewer than 2000 records. `--selftest` plants a redact turned into allow and an unknown class allowed in a temporary copy, requires each to turn the check red through a failing test and the untouched copy to stay green, and prints `selftest 3/3`.

Known differences:

- The Unicode tables come from Python 3.11 (Unicode 14.0.0). Another Python version may normalize some characters differently, and the generator refuses to run on a different Unicode version.
- Nesting depth is capped near 991 in Go. Python's limit depends on the interpreter's recursion limit, so inputs near that depth may differ.
- The entropy rule sums logarithms. Go and the C library can differ in the last bit, so a value within that margin of the threshold may fall on either side.
- The command line treats input files that are not valid UTF-8, or that contain encoded surrogates, as bad input (exit 2).

## Honesty

The cases are synthetic and were written for this repo. No language model runs in the loop: the gate and the evaluator import only the Python standard library and open no network connection. The expected results sit beside the cases the checks are scored against, so the match count is a consistency check and not a claim that the checks generalize. The key-shaped string in the AWS case is a documented example value planted as a test fixture, not a secret. Nothing here was run against production data.

## Limitations

- Pattern matching finds shapes, not meaning. A secret in an unfamiliar format or a name in prose is not detected. Redaction lowers exposure; it is not anonymization.
- Text is normalized (NFKC, then Unicode format characters such as zero-width space, joiners, word joiner, byte order mark and soft hyphen are stripped) before matching, so redaction output is built from the normalized text; other evasions are not caught: spelled-out digits, a combining mark inside the number (for example U+0335), or a number split across a line break.
- The registry is trusted input. The gate checks that an attestation is recent and complete; it does not check that the attestation is true.
- A valid chain proves the log was not edited after the fact. A truncated tail is only detectable if you keep the last hash and pass `--head`. Anyone with write access who rewrites the whole file consistently defeats it; anchor the head hash somewhere else.
- Provider ids, dates, thresholds (180 days, regions `us` and `eu`) are policy choices in `boundary.py`, set for this demonstration.
- Engineering evidence, not legal advice. No certification is claimed against any standard named above.
