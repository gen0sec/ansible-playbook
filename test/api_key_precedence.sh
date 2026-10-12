#!/usr/bin/env bash
# Checks which gen0sec_api_key the roles see for every documented way of
# setting it. Runs the real playbook.yml and the real role defaults
# against a throwaway local inventory; only the roles' tasks are replaced by a
# stub that records the variable, so nothing on the host is changed and no
# root is needed.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v ansible-playbook >/dev/null 2>&1; then
  echo "FAIL: ansible-playbook not found" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Unmodified playbook; real defaults; stub tasks.
cp "$here/playbook.yml" "$work/playbook.yml"
for role in synapse fail2ban; do
  mkdir -p "$work/roles/$role/tasks"
  ln -s "$here/roles/$role/defaults" "$work/roles/$role/defaults"
  cat >"$work/roles/$role/tasks/main.yml" <<STUB
---
- name: Record gen0sec_api_key seen by $role
  ansible.builtin.copy:
    content: "{{ gen0sec_api_key }}"
    dest: "{{ lookup('env', 'PROBE_DIR') }}/$role"
    mode: "0600"
STUB
done

printf "[defaults]\n" >"$work/ansible.cfg"

failures=0

# run_case <name> <expected> <setup-function> [extra ansible-playbook args...]
# setup-function runs in a fresh case directory and writes inventory/group_vars.
run_case() {
  local name="$1" expected="$2" setup="$3"
  shift 3
  local case_dir="$work/case-$name"
  mkdir -p "$case_dir/out" "$case_dir/group_vars"
  "$setup" "$case_dir"
  if ! ANSIBLE_CONFIG="$work/ansible.cfg" ANSIBLE_ROLES_PATH="$work/roles" \
    ANSIBLE_LOCALHOST_WARNING=False ANSIBLE_INVENTORY_UNPARSED_WARNING=False \
    PROBE_DIR="$case_dir/out" \
    ansible-playbook -i "$case_dir/inventory" "$work/playbook.yml" \
    --limit target "$@" >"$case_dir/log" 2>&1; then
    echo "FAIL [$name]: ansible-playbook failed" >&2
    cat "$case_dir/log" >&2
    failures=$((failures + 1))
    return 0
  fi
  local role got
  for role in synapse fail2ban; do
    if [ ! -f "$case_dir/out/$role" ]; then
      echo "FAIL [$name]: role $role did not run" >&2
      failures=$((failures + 1))
      continue
    fi
    got="$(cat "$case_dir/out/$role")"
    if [ "$got" = "$expected" ]; then
      echo "ok   [$name] $role: '$got'"
    else
      echo "FAIL [$name] $role: expected '$expected', got '$got'" >&2
      failures=$((failures + 1))
    fi
  done
}

hdr='target ansible_connection=local ansible_become=false ansible_python_interpreter=auto_silent'

setup_none()    { printf '[all]\n%s\n' "$hdr" >"$1/inventory"; }
setup_host()    { printf '[all]\n%s gen0sec_api_key=from-host\n' "$hdr" >"$1/inventory"; }
setup_group()   { printf '[all]\n%s\n[all:vars]\ngen0sec_api_key=from-group\n' "$hdr" >"$1/inventory"; }
setup_gvars()   {
  printf '[all]\n%s\n' "$hdr" >"$1/inventory"
  # The shipped example, as the README tells the operator to use it.
  sed 's/^# *gen0sec_api_key:.*/gen0sec_api_key: "from-group-vars-file"/' \
    "$here/group_vars/all_example.yml" >"$1/group_vars/all.yml"
}
setup_unedited() {
  printf '[all]\n%s\n' "$hdr" >"$1/inventory"
  # The shipped example copied without editing: it must not supply a key.
  cp "$here/group_vars/all_example.yml" "$1/group_vars/all.yml"
}
setup_alias()   { printf '[all]\n%s g0s_api_key=from-alias\n' "$hdr" >"$1/inventory"; }
setup_both()    { printf '[all]\n%s g0s_api_key=from-alias gen0sec_api_key=from-host\n' "$hdr" >"$1/inventory"; }

run_case nothing-set ""                    setup_none
run_case host-var    "from-host"           setup_host
run_case group-var   "from-group"          setup_group
run_case group_vars  "from-group-vars-file" setup_gvars
run_case extra-var   "from-extra"          setup_host -e gen0sec_api_key=from-extra
run_case alias       "from-alias"          setup_alias
run_case unedited-example ""                setup_unedited
run_case unedited-example-alias "from-alias-extra" setup_unedited -e g0s_api_key=from-alias-extra
run_case key-beats-alias "from-host"       setup_both

if [ "$failures" -ne 0 ]; then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "all api key precedence checks passed"
