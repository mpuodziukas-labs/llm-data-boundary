#!/bin/bash
# One command, whole proof: table, tests, mutants. Exit 0 only if all three pass.
set -uo pipefail
cd "$(dirname "$0")"
PY="${PYTHON:-python3}"   # the interpreter on PATH, so CI uses the one setup-python installed pytest into
"$PY" evaluate.py || exit 1
echo
"$PY" -m pytest -q -p no:cacheprovider || exit 1
echo
"$PY" mutants.py
