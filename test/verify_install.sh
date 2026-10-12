#!/usr/bin/env bash
# Runs INSIDE the test container, as root, after a playbook run. Checks the
# outcome of the install, not that the playbook said ok.
#
#   verify_install.sh <expected package> <deb|rpm>
#
# GEN0SEC_REPO_KEY must be in the environment (docker exec -e GEN0SEC_REPO_KEY).
# It is only ever read through a file descriptor, never put in an argument list.
set -u

want_pkg="${1:?expected package}"
family="${2:?deb or rpm}"
: "${GEN0SEC_REPO_KEY:?GEN0SEC_REPO_KEY must be set}"

rc=0
fail() { echo "FAIL $1"; rc=1; }
ok() { echo "ok   $1"; }

case "$family" in
  deb) cred=/etc/apt/auth.conf.d/gen0sec.conf ;;
  rpm) cred=/etc/yum.repos.d/gen0sec.repo ;;
  *) echo "usage: $0 <package> <deb|rpm>" >&2; exit 2 ;;
esac

is_installed() {
  if [ "$family" = deb ]; then dpkg-query -W -f='${Status}' "$1" 2>/dev/null | /usr/bin/grep -q '^install ok installed'
  else rpm -q --quiet "$1"; fi
}

# 1. Exactly one of the four packages, and it is the expected one.
installed=()
for p in synapse-agent synapse-agent-ml synapse-proxy synapse-proxy-ml; do
  is_installed "$p" && installed+=("$p")
done
if [ "${#installed[@]}" -eq 1 ] && [ "${installed[0]}" = "$want_pkg" ]; then
  ok "package: only $want_pkg is installed"
else
  fail "package: want only $want_pkg, found: ${installed[*]:-none}"
fi

# 2. The unit is named after the package, reads /etc/synapse/config.yaml, is
#    enabled, and runs.
if ! unit="$(systemctl cat "$want_pkg" 2>&1)"; then
  fail "unit: systemctl cat $want_pkg failed"
elif ! /usr/bin/grep -E '^ExecStart=.*--config /etc/synapse/config\.yaml' <<< "$unit" | /usr/bin/grep -q '/usr/bin/synapse'; then
  fail "unit: ExecStart of $want_pkg does not run /usr/bin/synapse with --config /etc/synapse/config.yaml"
else
  ok "unit: $want_pkg runs /usr/bin/synapse --config /etc/synapse/config.yaml"
fi
if systemctl is-enabled --quiet "$want_pkg"; then ok "unit: enabled"; else fail "unit: $want_pkg is not enabled"; fi
active=no
for _ in $(seq 1 30); do
  if systemctl is-active --quiet "$want_pkg"; then active=yes; break; fi
  sleep 1
done
if [ "$active" = yes ]; then ok "unit: active"; else
  fail "unit: $want_pkg did not become active within 30s"
  systemctl status "$want_pkg" --no-pager -l 2>&1 | tail -n 15
fi
for other in synapse-agent synapse-agent-ml synapse-proxy synapse-proxy-ml; do
  if [ "$other" != "$want_pkg" ] && systemctl is-active --quiet "$other" 2>/dev/null; then
    fail "unit: $other is still active"
  fi
done

# 3. Files: config 0640, the credential file 0600, /etc/synapse (and the proxy's
#    certs) 0750 as the packages ship them, all root-owned.
check_file() { # path mode
  local got; got="$(stat -c '%a %U:%G' "$1" 2>/dev/null)" || { fail "file: $1 is missing"; return; }
  if [ "$got" = "$2 root:root" ]; then ok "file: $1 is $got"; else fail "file: $1 is '$got', want '$2 root:root'"; fi
}
check_file /etc/synapse/config.yaml 640
check_file "$cred" 600
check_file /etc/synapse 750
case "$want_pkg" in synapse-proxy*) check_file /etc/synapse/certs 750 ;; esac

# 4. The credential is on disk in the credential file and nowhere else. The key
#    is handed to grep as a pattern file on a descriptor, not as an argument.
#    This also covers the ansible logs, which are written inside the container.
leaks="$(grep -rlsF -f <(printf '%s' "$GEN0SEC_REPO_KEY") \
  --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev --exclude-dir=work / 2>/dev/null \
  | /usr/bin/grep -vxF -- "$cred")"
if [ -z "$leaks" ]; then ok "secret: the key is in no file but $cred"; else
  fail "secret: the key was found in:"; echo "$leaks"
fi
if grep -qsF -f <(printf '%s' "$GEN0SEC_REPO_KEY") "$cred"; then ok "secret: $cred holds the key"; else
  fail "secret: $cred does not hold the key; the credential was not written"
fi

exit "$rc"
