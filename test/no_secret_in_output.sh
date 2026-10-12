#!/usr/bin/env bash
# Checks that neither credential reaches ansible's output, even at the most
# talkative settings: `--check --diff -vvv`.
#
# The two credentials are the repository key (GEN0SEC_REPO_KEY) and the API key
# (gen0sec_api_key). Both are replaced by markers here, and the whole output is
# searched for them. The tasks that carry a secret are tagged gen0sec_secrets;
# the test runs only those (plus the selection tasks they depend on) with the
# host facts stubbed, in check mode, so it needs no root, no network and no
# package manager, and it changes nothing on the machine. Check mode with
# --diff is where an unprotected copy, template or repository task would print
# its content. The markers reach the role the way real keys do: the repository
# key through the environment, the API key through a 0600 vars file, never on
# the command line.
#
# Two controls keep this from passing vacuously:
#   1. the output must contain ansible's no_log notice, which proves the
#      protected tasks ran and were censored rather than skipped;
#   2. a deliberately unprotected copy of the same marker must be found by the
#      same search, which proves the search can see a leak.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v ansible-playbook >/dev/null 2>&1; then
  echo "FAIL: ansible-playbook not found" >&2
  exit 1
fi
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

REPO_MARKER="REPOKEY-MARKER-$$-$RANDOM"
API_MARKER="APIKEY-MARKER-$$-$RANDOM"
mkdir -p "$OUT/yum.repos.d"
( umask 077; printf 'gen0sec_api_key: "%s"\n' "$API_MARKER" > "$OUT/secrets.yml" )

# The template task finds config.yaml.j2 next to the playbook, as it would in the role.
ln -s "$ROOT/roles/synapse/templates" "$OUT/templates"

cat > "$OUT/harness.yml" <<'PLAY'
- hosts: localhost
  connection: local
  gather_facts: false
  vars_files:
    - "{{ role_dir }}/defaults/main.yml"
  tasks:
    - ansible.builtin.import_tasks: "{{ role_dir }}/tasks/select.yml"
      tags: always
    - ansible.builtin.import_tasks: "{{ role_dir }}/tasks/{{ repo_tasks }}"
    - ansible.builtin.import_tasks: "{{ role_dir }}/tasks/config.yml"
  handlers:
    - name: Restart synapse service
      ansible.builtin.debug:
        msg: restart
PLAY

cat > "$OUT/leaky.yml" <<'PLAY'
- hosts: localhost
  connection: local
  gather_facts: false
  vars_files:
    - "{{ role_dir }}/defaults/main.yml"
  tasks:
    - name: Deliberately unprotected copy
      ansible.builtin.copy:
        content: "{{ gen0sec_repo_key }}"
        dest: "{{ leak_dest }}"
        mode: "0600"
PLAY

DEB='{"ansible_facts":{"os_family":"Debian","distribution":"Ubuntu","distribution_major_version":"20","pkg_mgr":"apt","default_ipv4":{"interface":"eth0"}}}'
RPM='{"ansible_facts":{"os_family":"RedHat","distribution":"OracleLinux","distribution_major_version":"9","pkg_mgr":"dnf","default_ipv4":{"interface":"eth0"}}}'

rc=0
fail() { echo "FAIL $1"; rc=1; }

# play <name> <playbook> <tags|-> <extra vars...>: output in $OUT/<name>.log
play() {
  local name="$1" book="$2" tags="$3"; shift 3
  local args=()
  [ "$tags" != "-" ] && args+=(--tags "$tags")
  GEN0SEC_REPO_KEY="$REPO_MARKER" ANSIBLE_BECOME=False ANSIBLE_LOCALHOST_WARNING=False ANSIBLE_INVENTORY_UNPARSED_WARNING=False \
    ansible-playbook -i localhost, "$book" --check --diff -vvv "${args[@]}" \
    -e "role_dir=$ROOT/roles/synapse" -e "@$OUT/secrets.yml" \
    -e "synapse_yum_reposdir=$OUT/yum.repos.d" "$@" </dev/null > "$OUT/$name.log" 2>&1
}

check_family() { # <name> <facts> <repo task file> <task name that must have run>
  local name="$1"
  play "$name" "$OUT/harness.yml" gen0sec_secrets -e "$2" -e "repo_tasks=$3"
  local st=$?
  if [ "$st" -ne 0 ]; then fail "$name: the play failed (exit $st)"; cat "$OUT/$name.log"; return; fi
  local ok=1 m
  for m in "$REPO_MARKER" "$API_MARKER"; do
    if /usr/bin/grep -qF -- "$m" "$OUT/$name.log"; then fail "$name: a secret is in the output"; ok=0; fi
  done
  if ! /usr/bin/grep -q 'output has been hidden due to the fact that .no_log: true.' "$OUT/$name.log"; then
    fail "$name: control: no no_log notice in the output; the protected tasks did not run"; ok=0
  fi
  for t in "$4" "Generate config.yaml from template"; do
    if ! /usr/bin/grep -qF -- "TASK [$t]" "$OUT/$name.log"; then
      fail "$name: control: task '$t' did not run"; ok=0
    fi
  done
  [ "$ok" -eq 1 ] && echo "ok   $name"
}

check_family debian "$DEB" repo_debian.yml "Write the apt credentials for the Gen0Sec repository"
check_family redhat "$RPM" repo_redhat.yml "Define the Gen0Sec yum repository"

# Control 2: the search must be able to see a leak.
play leaky "$OUT/leaky.yml" - -e "$DEB" -e "leak_dest=$OUT/leak.txt"
if /usr/bin/grep -qF -- "$REPO_MARKER" "$OUT/leaky.log"; then
  echo "ok   control: an unprotected copy is visible to the search"
else
  fail "control: an unprotected copy was not visible; the search proves nothing"
  cat "$OUT/leaky.log"
fi

exit "$rc"
