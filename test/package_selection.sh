#!/usr/bin/env bash
# Checks which package the role installs for every mode, with and without the
# ML models, on both package families: the package name, the packages that
# conflict with it, the version spec (apt writes name=VER-1, dnf name-VER-1),
# and that bad input is refused.
#
# It runs the role's tasks/select.yml in a throwaway local play. The host facts
# are passed as extra vars (gather_facts is off), so the result does not depend
# on the machine running the test, and nothing on it is changed (ansible.cfg
# asks for sudo; the test turns that off). It needs
# ansible-playbook only: no network, no root, no package manager.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v ansible-playbook >/dev/null 2>&1; then
  echo "FAIL: ansible-playbook not found" >&2
  exit 1
fi
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

cat > "$OUT/select.yml" <<'PLAY'
- hosts: localhost
  connection: local
  gather_facts: false
  vars_files:
    - "{{ role_dir }}/defaults/main.yml"
  tasks:
    - ansible.builtin.include_tasks: "{{ role_dir }}/tasks/select.yml"
    - ansible.builtin.copy:
        dest: "{{ out }}"
        mode: "0600"
        content: |
          package={{ synapse_package }}
          spec={{ synapse_package_spec }}
          family={{ synapse_pkg_family }}
          conflicts={{ synapse_conflicting_packages | join(',') }}
PLAY

DEB='{"ansible_facts":{"os_family":"Debian","distribution":"Ubuntu","distribution_major_version":"20","pkg_mgr":"apt"}}'
RPM='{"ansible_facts":{"os_family":"RedHat","distribution":"OracleLinux","distribution_major_version":"9","pkg_mgr":"dnf"}}'
EL7='{"ansible_facts":{"os_family":"RedHat","distribution":"CentOS","distribution_major_version":"7","pkg_mgr":"yum"}}'

# The key comes from the environment, as in real use. It is a marker, not a
# credential.
KEY='select-test-key-not-a-secret'

# run <facts-json> <extra-vars-json> [key]: sets $log and $status
run() {
  log="$OUT/run.log"
  rm -f "$OUT/result"
  GEN0SEC_REPO_KEY="${3-$KEY}" ANSIBLE_BECOME=False ANSIBLE_LOCALHOST_WARNING=False ANSIBLE_INVENTORY_UNPARSED_WARNING=False \
    ansible-playbook -i localhost, "$OUT/select.yml" \
    -e "role_dir=$ROOT/roles/synapse" -e "out=$OUT/result" \
    -e "$1" -e "$2" </dev/null > "$log" 2>&1
  status=$?
}

rc=0
fail() { echo "FAIL $1"; rc=1; }

# expect_ok <name> <facts> <vars> <package> <spec> <family> <conflicts>
expect_ok() {
  local name="$1" want
  run "$2" "$3"
  if [ "$status" -ne 0 ]; then fail "$name: select.yml failed"; cat "$log"; return; fi
  want="package=$4
spec=$5
family=$6
conflicts=$7"
  if [ "$(cat "$OUT/result")" != "$want" ]; then
    fail "$name: wrong selection"; echo "--- want"; echo "$want"; echo "--- got"; cat "$OUT/result"
  else
    echo "ok   $name"
  fi
}

# expect_refused <name> <facts> <vars> <ERE the message must match> [key]
expect_refused() {
  local name="$1"
  run "$2" "$3" ${5+"$5"}
  if [ "$status" -eq 0 ]; then fail "$name: not refused"
  elif ! /usr/bin/grep -qE -- "$4" "$log"; then fail "$name: refused without a message matching: $4"; cat "$log"
  else echo "ok   $name"; fi
}

# Package and conflicts, every mode x ml x family.
expect_ok deb_agent       "$DEB" '{}' synapse-agent synapse-agent deb synapse-agent-ml,synapse-proxy,synapse-proxy-ml
expect_ok deb_agent_ml    "$DEB" '{"synapse_ml":true}' synapse-agent-ml synapse-agent-ml deb synapse-agent,synapse-proxy,synapse-proxy-ml
expect_ok deb_proxy       "$DEB" '{"synapse_config_mode":"proxy"}' synapse-proxy synapse-proxy deb synapse-agent,synapse-agent-ml,synapse-proxy-ml
expect_ok deb_proxy_ml    "$DEB" '{"synapse_config_mode":"proxy","synapse_ml":true}' synapse-proxy-ml synapse-proxy-ml deb synapse-agent,synapse-agent-ml,synapse-proxy
expect_ok rpm_agent       "$RPM" '{}' synapse-agent synapse-agent rpm synapse-agent-ml,synapse-proxy,synapse-proxy-ml
expect_ok rpm_agent_ml    "$RPM" '{"synapse_ml":true}' synapse-agent-ml synapse-agent-ml rpm synapse-agent,synapse-proxy,synapse-proxy-ml
expect_ok rpm_proxy       "$RPM" '{"synapse_config_mode":"proxy"}' synapse-proxy synapse-proxy rpm synapse-agent,synapse-agent-ml,synapse-proxy-ml
expect_ok rpm_proxy_ml    "$RPM" '{"synapse_config_mode":"proxy","synapse_ml":true}' synapse-proxy-ml synapse-proxy-ml rpm synapse-agent,synapse-agent-ml,synapse-proxy

# Version spec per family. A pin is X.Y.Z; the package release is always -1.
expect_ok deb_version     "$DEB" '{"synapse_version":"0.9.0"}' synapse-agent 'synapse-agent=0.9.0-1' deb synapse-agent-ml,synapse-proxy,synapse-proxy-ml
expect_ok rpm_version     "$RPM" '{"synapse_version":"0.9.0"}' synapse-agent 'synapse-agent-0.9.0-1' rpm synapse-agent-ml,synapse-proxy,synapse-proxy-ml
expect_ok deb_version_rc  "$DEB" '{"synapse_version":"0.9.0~rc.1","synapse_config_mode":"proxy","synapse_ml":true}' synapse-proxy-ml 'synapse-proxy-ml=0.9.0~rc.1-1' deb synapse-agent,synapse-agent-ml,synapse-proxy
expect_ok rpm_version_rc  "$RPM" '{"synapse_version":"0.9.0~rc.1"}' synapse-agent 'synapse-agent-0.9.0~rc.1-1' rpm synapse-agent-ml,synapse-proxy,synapse-proxy-ml

# Refusals. The messages must say what to do; none may contain the key.
expect_refused empty_key        "$DEB" '{}' 'Repository Access' ''
expect_refused whitespace_key   "$DEB" '{}' 'Repository Access' '   '
expect_refused key_with_space   "$DEB" '{}' 'Repository Access' 'two words'
expect_refused bad_mode         "$DEB" '{"synapse_config_mode":"sidecar"}' "synapse_config_mode"
expect_refused bad_version      "$DEB" '{"synapse_version":"1.0 evil"}' "synapse_version"
expect_refused bad_state        "$DEB" '{"synapse_package_state":"absent"}' "synapse_package_state"
expect_refused version_latest   "$DEB" '{"synapse_version":"0.9.0","synapse_package_state":"latest"}' "synapse_version"
expect_refused bad_service_state "$DEB" '{"synapse_service_state":"restarted"}' "synapse_service_state"
expect_refused el7_yum          "$EL7" '{}' 'version 8 or newer'
expect_refused unsupported_os   '{"ansible_facts":{"os_family":"Suse","distribution":"SLES","distribution_major_version":"15","pkg_mgr":"zypper"}}' '{}' 'Debian|RedHat'

# The refusals must never print the key.
k='two words'
run "$DEB" '{}' "$k"
if /usr/bin/grep -q -- "$k" "$log"; then fail "key_not_printed: the output contains the key"; else echo "ok   key_not_printed"; fi

exit "$rc"
