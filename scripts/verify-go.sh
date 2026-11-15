#!/usr/bin/env bash
# Verify the Go port of the decision point.
#
#   scripts/verify-go.sh             go vet, go test (cases, parity, normalization, fuzz seeds),
#                                    then the 28 case folders through the built CLI
#   scripts/verify-go.sh --selftest  plant two defects in a temporary copy and require the check
#                                    to go red on each, and green on the untouched copy
#
# Exit 0 only when every step passed. GO may name the go binary (default: go).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO="${GO:-go}"
MIN_PARITY=2000
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP:?}"' EXIT

command -v "$GO" >/dev/null 2>&1 || { echo "verify-go: go not found (set GO=/path/to/go)" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "verify-go: python3 not found" >&2; exit 2; }

# compare_case EXPECTED.json EXIT_CODE STDOUT_FILE: exit 0 when the CLI result equals expected.json
compare_case() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import sys

exp = json.load(open(sys.argv[1]))
rc = int(sys.argv[2])
if rc != exp["exit"]:
    sys.exit("exit %d, expected %d" % (rc, exp["exit"]))
if exp["exit"] == 2:
    sys.exit(0)
got = json.load(open(sys.argv[3]))
want = {"decision": exp["decision"], "rule": exp["rule"], "classes": exp["classes"],
        "redacted_payload": exp.get("redacted_payload")}
if got != want:
    sys.exit("got %s, expected %s" % (json.dumps(got, sort_keys=True), json.dumps(want, sort_keys=True)))
PY
}

# check TREE: run every step against TREE/go and TREE/cases. Returns 1 at the first failure.
# Callers must use it as the condition of an if, so each step ends in an explicit "|| return 1".
check() {
  local tree=$1 work log n=0 ok=0 dir name now rc
  work="$(mktemp -d "$TMP/w.XXXXXX")"
  log="$work/test.log"

  (cd "$tree/go" && "$GO" vet ./...) >"$work/vet.log" 2>&1 || { cat "$work/vet.log"; echo "FAIL go vet"; return 1; }
  echo "go vet: clean"

  (cd "$tree/go" && "$GO" test ./... -count=1 -v) >"$log" 2>&1 || { tail -n 30 "$log"; echo "FAIL go test"; return 1; }
  echo "go test: ok"

  local parity
  parity="$(grep -Eo 'parity [0-9]+/[0-9]+' "$log" | head -n 1 | cut -d' ' -f2)" || true
  if [[ ! "$parity" =~ ^([0-9]+)/([0-9]+)$ ]] || [[ "${BASH_REMATCH[1]}" != "${BASH_REMATCH[2]}" ]] \
    || (( BASH_REMATCH[2] < MIN_PARITY )); then
    echo "FAIL parity '${parity}' (need N/N with N >= $MIN_PARITY)"
    return 1
  fi
  echo "parity: $parity"

  (cd "$tree/go" && "$GO" build -o "$work/pdp" ./cmd/pdp) || { echo "FAIL go build"; return 1; }
  for dir in "$tree"/cases/*/; do
    name="$(basename "$dir")"
    n=$((n + 1))
    now="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["now"])' "$dir/expected.json")" \
      || { echo "FAIL $name: unreadable expected.json"; return 1; }
    rc=0
    "$work/pdp" --registry "$dir/registry.json" --now "$now" <"$dir/request.json" >"$work/out.json" 2>"$work/err.txt" || rc=$?
    if compare_case "$dir/expected.json" "$rc" "$work/out.json"; then
      ok=$((ok + 1))
    else
      echo "FAIL case $name"
    fi
  done
  echo "cases (cli): $ok/$n"
  if (( n == 0 )) || (( ok != n )); then
    return 1
  fi
  return 0
}

# plant TREE FILE OLD NEW: replace the single occurrence of OLD in TREE/FILE with NEW; fail if absent
plant() {
  local f="$1/$2" before
  before="$(cat "$f")"
  PLANT_OLD="$3" PLANT_NEW="$4" python3 - "$f" <<'PY'
import os
import sys

p = sys.argv[1]
s = open(p, encoding="utf-8").read()
old, new = os.environ["PLANT_OLD"], os.environ["PLANT_NEW"]
if s.count(old) != 1:
    sys.exit("planted-defect anchor not found exactly once in %s" % p)
open(p, "w", encoding="utf-8").write(s.replace(old, new))
PY
  [[ "$(cat "$f")" != "$before" ]] || { echo "selftest: planting changed nothing" >&2; return 1; }
}

# red_by_tests LOG: the failure came from a failing test, not from code that did not compile
red_by_tests() {
  grep -q 'FAIL go test' "$1" && grep -q -- '--- FAIL' "$1" && ! grep -q 'build failed' "$1"
}

selftest() {
  local pass=0 total=0 copy
  fresh() {
    copy="$(mktemp -d "$TMP/copy.XXXXXX")"
    cp -R "$ROOT/go" "$copy/go"
    cp -R "$ROOT/cases" "$copy/cases"
  }

  total=$((total + 1))
  fresh
  if check "$copy" >"$TMP/clean.log" 2>&1; then
    echo "selftest 1: untouched copy is GREEN (as required)"
    pass=$((pass + 1))
  else
    tail -n 20 "$TMP/clean.log"
    echo "selftest 1: untouched copy is RED (it must be GREEN)"
  fi

  total=$((total + 1))
  fresh
  plant "$copy" go/pdp/pdp.go 'return out(Redact, "R10_REDACT_THEN_ALLOW", &s)' \
    '_ = s
		return out(Allow, "R13_ALLOW", nil)' || exit 2
  if check "$copy" >"$TMP/m1.log" 2>&1; then
    echo "selftest 2: a redact flipped to allow went unnoticed (it must be RED)"
  elif red_by_tests "$TMP/m1.log"; then
    echo "selftest 2: a redact flipped to allow is RED (as required)"
    pass=$((pass + 1))
  else
    echo "selftest 2: RED, but not from a failing test (planted code did not build?)"
  fi

  total=$((total + 1))
  fresh
  plant "$copy" go/pdp/pdp.go '!ok || !validLabels[s]' '!ok || (s == "" && !validLabels[s])' || exit 2
  if check "$copy" >"$TMP/m2.log" 2>&1; then
    echo "selftest 3: an unknown class allowed went unnoticed (it must be RED)"
  elif red_by_tests "$TMP/m2.log"; then
    echo "selftest 3: an unknown class allowed is RED (as required)"
    pass=$((pass + 1))
  else
    echo "selftest 3: RED, but not from a failing test (planted code did not build?)"
  fi

  echo "selftest $pass/$total"
  [[ "$pass" -eq "$total" ]]
}

case "${1:-}" in
  "")
    if check "$ROOT"; then
      echo "verify-go: GREEN"
    else
      echo "verify-go: RED" >&2
      exit 1
    fi
    ;;
  --selftest)
    selftest
    ;;
  *)
    echo "usage: scripts/verify-go.sh [--selftest]" >&2
    exit 2
    ;;
esac
