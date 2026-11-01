# Verifying this repository

Purpose: Show that a policy gate decides whether text may go to an LLM provider from the provider's recorded attributes, fails closed on unknown, stale, contradictory or malformed input, and writes a hash-chained evidence log that a verifier refuses when tampered.

Verify: `bash run.sh`

Pass condition: exit code 0 and this exact output line (leading spaces ignored): `mutants: 29/29 killed`

Scope: synthetic data, offline, standard library only at run time (the test step needs pytest), under 60 seconds.

Limitations: Pattern matching finds shapes, not meaning. The provider registry is trusted input. Framework mappings are the author's reading, not an auditor's opinion. Not legal advice, no certification claimed.

Anything else = not verified.
