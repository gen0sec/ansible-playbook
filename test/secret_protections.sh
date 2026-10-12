#!/usr/bin/env bash
# Static check of the secret protections, run over every task file of every
# role (test/check_secret_protections.py holds the rules and documents them).
#
# The dynamic test (no_secret_in_output.sh) shows that a leak would be seen in
# ansible's output; this one pins each protection on its own, so removing a
# single `no_log` or `diff: false` from any task fails here even where
# ansible's output would not show it. Each rule is also proven on a fixture
# that breaks exactly that rule: a checker that flags nothing would pass the
# real roles vacuously.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT/test/check_secret_protections.py"
FIX="$ROOT/test/fixtures/secret_protections"
rc=0
fail() { echo "FAIL $1"; rc=1; }

# 1. The real roles are clean.
shopt -s nullglob
real=("$ROOT"/roles/*/tasks/*.yml "$ROOT"/roles/*/handlers/*.yml)
if [ "${#real[@]}" -eq 0 ]; then fail "no role task files found"; fi
if out="$(python3 "$CHECK" "${real[@]}" 2>&1)"; then
  echo "ok   roles: ${#real[@]} task files, every secret-bearing task is protected"
else
  fail "roles: a secret-bearing task is not protected"; echo "$out"
fi

# 2. The good fixture is clean (the checker does not flag everything).
if python3 "$CHECK" "$FIX/good.yml" > /dev/null 2>&1; then echo "ok   fixture good: clean"; else
  fail "fixture good: flagged, so the checker is too strict"; python3 "$CHECK" "$FIX/good.yml"
fi

# 3. Every other fixture is flagged, for the rule its name starts with.
expect() { # fixture rule
  local out
  if out="$(python3 "$CHECK" "$FIX/$1.yml" 2>&1)"; then fail "fixture $1: not flagged"; return; fi
  if grep -q "\\[$2\\]" <<< "$out"; then echo "ok   fixture $1: flagged [$2]"; else
    fail "fixture $1: flagged, but not for [$2]"; echo "$out"
  fi
}
expect no_log_missing_fact   no_log
expect no_log_missing_copy   no_log
expect no_log_false          no_log
expect no_log_missing_nested no_log
expect diff_missing_copy     diff
expect diff_missing_template diff
expect diff_missing_yum      diff
expect forbidden_command     forbidden-module
expect forbidden_debug       forbidden-module
expect forbidden_assert_msg  secret-in-message
expect forbidden_fail        secret-in-message
expect forbidden_fail_when_interpolated secret-in-message
expect template_secret_unlisted no_log

exit "$rc"
