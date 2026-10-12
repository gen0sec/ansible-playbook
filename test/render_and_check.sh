#!/usr/bin/env bash
# Render roles/synapse/templates/config.yaml.j2 for several variable
# sets and validate each result with `synapse --check-config`.
#
# --check-config is not in a released synapse binary. Without one the binary
# step is skipped, visibly: each variant prints a SKIP line and the run ends
# with a count, while the render and the line checks below still run. To run the
# full check, point it at a build that has the flag:
#
#   SYNAPSE_BIN=/path/to/synapse test/render_and_check.sh
#
# A variant passes when the checker exits 0 and reports no unused (unknown)
# config key ("Unused config options in ..."). The checker also warns that the
# default security_rules.yaml is absent; that is about the host, not the
# template, and is ignored. Needs ansible-playbook.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Only the default lookup of `synapse` on PATH may be skipped. A SYNAPSE_BIN
# that was set explicitly but is missing or has no --check-config is an error.
if [ -n "${SYNAPSE_BIN:-}" ]; then explicit_bin=1; else explicit_bin=0; fi
SYNAPSE_BIN="${SYNAPSE_BIN:-synapse}"
have_bin=0
skipped=0
if ! command -v "$SYNAPSE_BIN" >/dev/null 2>&1; then
  if [ "$explicit_bin" -eq 1 ]; then
    echo "FAIL: SYNAPSE_BIN='$SYNAPSE_BIN' was set but is not an executable"; exit 1
  fi
  echo "SKIP: synapse binary '$SYNAPSE_BIN' not found; --check-config will not run (set SYNAPSE_BIN to run it)"
elif ! "$SYNAPSE_BIN" --help 2>&1 | grep -q -- '--check-config'; then
  if [ "$explicit_bin" -eq 1 ]; then
    echo "FAIL: SYNAPSE_BIN='$SYNAPSE_BIN' has no --check-config flag"; exit 1
  fi
  echo "SKIP: '$SYNAPSE_BIN' has no --check-config flag; it will not run (set SYNAPSE_BIN to a build that has it)"
else
  have_bin=1
fi
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

cat > "$OUT/render.yml" <<'PLAY'
- hosts: localhost
  connection: local
  gather_facts: false
  vars_files:
    - "{{ role_dir }}/defaults/main.yml"
    - "{{ group_vars_file }}"
  tasks:
    - ansible.builtin.template:
        src: "{{ role_dir }}/templates/config.yaml.j2"
        dest: "{{ out }}"
PLAY

# name|extra vars (JSON)|ERE that must match the rendered file|ERE that must not match
# (the last two are optional)
VARIANTS=(
  'agent|{"synapse_config_mode":"agent"}|^platform:|^proxy:'
  'agent_default_mode|{}'
  'proxy|{"synapse_config_mode":"proxy"}|^proxy:'
  'proxy_geoip_defaults|{"synapse_config_mode":"proxy"}|^      path: "/var/lib/synapse/ipinfo_lite.mmdb"$|^      path: "?/var/lib/synapse"?$|GeoLite2-(ASN|City)'
  'proxy_redis_disabled|{"synapse_config_mode":"proxy","redis_enabled":false}|^    url: ""$'
  'proxy_redis_disabled_remote_url|{"synapse_config_mode":"proxy","redis_enabled":false,"synapse_config_redis_url":"redis://r.example:6379/0"}|^    url: "redis://r.example:6379/0"$'
  'proxy_clamav|{"synapse_config_mode":"proxy","clamav_enabled":true,"synapse_config_content_scanning_enabled":true,"synapse_config_content_scanning_clamav_server":"127.0.0.1:3310"}'
  'proxy_no_clamav|{"synapse_config_mode":"proxy","clamav_enabled":false,"synapse_config_content_scanning_enabled":false}'
  'proxy_redis_ssl|{"synapse_config_mode":"proxy","redis_enabled":true,"synapse_config_redis_ssl":true,"synapse_config_redis_ssl_ca_cert_path":"/etc/ssl/ca.pem","synapse_config_redis_ssl_client_cert_path":"/etc/ssl/c.pem","synapse_config_redis_ssl_client_key_path":"/etc/ssl/c.key","synapse_config_redis_ssl_insecure":false}'
  'agent_fingerprint_log_file|{"synapse_config_mode":"agent","synapse_config_logging_fingerprint_log_file":"/var/log/synapse/fp.log"}'
  'proxy_api_key|{"synapse_config_mode":"proxy","synapse_config_platform_api_key":"test-key"}'
  'proxy_acme|{"synapse_config_mode":"proxy","synapse_config_acme_enabled":true,"synapse_config_acme_email":"admin@example.com"}'
)

rc=0
for v in "${VARIANTS[@]}"; do
  IFS='|' read -r name vars must_match must_not_match <<< "$v"
  cfg="$OUT/$name.yaml"
  if ! ANSIBLE_LOCALHOST_WARNING=False ANSIBLE_INVENTORY_UNPARSED_WARNING=False \
      ansible-playbook -i localhost, "$OUT/render.yml" \
      -e "role_dir=$ROOT/roles/synapse" \
      -e "group_vars_file=$ROOT/group_vars/all_example.yml" \
      -e "out=$cfg" \
      -e '{"ansible_facts":{"default_ipv4":{"interface":"eth0"}}}' \
      -e "$vars" > "$OUT/$name.render.log" 2>&1; then
    echo "FAIL $name: render error"; cat "$OUT/$name.render.log"; rc=1; continue
  fi
  st=0
  : > "$OUT/$name.check.log"
  if [ "$have_bin" -eq 1 ]; then
    "$SYNAPSE_BIN" --check-config -c "$cfg" \
      --upstream-conf "$ROOT/roles/synapse/files/upstreams_example.yaml" > "$OUT/$name.check.log" 2>&1
    st=$?
  fi
  if [ "$st" -ne 0 ] || grep -qiE 'unused config|unknown' "$OUT/$name.check.log"; then
    echo "FAIL $name (exit $st)"; cat "$OUT/$name.check.log"; rc=1
  elif [ -n "${must_match:-}" ] && ! grep -qE -- "$must_match" "$cfg"; then
    echo "FAIL $name: rendered config lacks a line matching: $must_match"; rc=1
  elif [ -n "${must_not_match:-}" ] && grep -qE -- "$must_not_match" "$cfg"; then
    echo "FAIL $name: rendered config has a line matching: $must_not_match"; rc=1
  elif [ "$have_bin" -eq 0 ]; then
    echo "SKIP $name: rendered and line checks passed; --check-config not run (no usable synapse binary)"
    skipped=$((skipped + 1))
  else
    echo "ok   $name"
  fi
done

# Inventories that still set a pre-rename variable must be refused by the role
# instead of having the setting silently dropped.
cat > "$OUT/legacy.yml" <<'PLAY'
- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - ansible.builtin.include_tasks: "{{ role_dir }}/tasks/check_legacy_vars.yml"
PLAY
run_legacy() { # extra-vars JSON
  ANSIBLE_LOCALHOST_WARNING=False ANSIBLE_INVENTORY_UNPARSED_WARNING=False \
    ansible-playbook -i localhost, "$OUT/legacy.yml" -e "role_dir=$ROOT/roles/synapse" -e "$1" 2>&1
}
if out="$(run_legacy '{}')"; then echo "ok   legacy_vars_none"; else
  echo "FAIL legacy_vars_none: refused a clean inventory"; echo "$out"; rc=1; fi
for var in synapse_config_arxignis_log_sending_enabled synapse_config_pingora_proxy_address_http \
    synapse_config_bpf_stats_enabled synapse_config_tcp_fingerprint_enabled \
    synapse_config_network_disable_xdp synapse_config_daemon_stdout synapse_config_daemon_stderr; do
  if out="$(run_legacy "{\"$var\":\"x\"}")"; then
    echo "FAIL legacy_vars $var: not refused"; rc=1
  elif ! grep -q "$var" <<< "$out"; then
    echo "FAIL legacy_vars $var: refused without naming it"; echo "$out"; rc=1
  else
    echo "ok   legacy_vars $var"
  fi
done
if [ "$skipped" -gt 0 ]; then
  echo "NOTE: $skipped variant(s) were not checked with --check-config (no usable synapse binary)"
fi
exit "$rc"
