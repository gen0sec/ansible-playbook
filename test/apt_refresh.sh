#!/usr/bin/env bash
# Checks when the role refreshes the apt package index, without a network, a
# package manager or root.
#
# The case that matters: a run with a wrong key leaves the source and the
# keyring in place, so the run that follows with the corrected key changes
# only the credential. If the refresh then depended on the source or keyring
# alone it would be skipped, install.yml would trust an index that is less than
# an hour old and the install would fail with "No package matching". So the
# credential, the keyring and the source must each force the refresh, and
# nothing changed must not.
#
# The second case: a run that fails at the refresh for a reason unrelated to
# the credential (an outage, a 5xx) leaves apt with no index for the source,
# and the next run changes nothing. The refresh must then be forced by the
# missing index file, and only by that: with the index present and nothing
# changed it must stay skipped.
#
# The test takes the tasks "Look for the fetched package index ..." and "Decide
# whether the package index needs refreshing" out of repo_debian.yml by name
# and runs them with stubbed results and a scratch apt lists directory. It also
# checks that the refresh task uses the decision. REPO_DEBIAN overrides the
# file (to run the test against another version of it).
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FILE="${REPO_DEBIAN:-$ROOT/roles/synapse/tasks/repo_debian.yml}"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

if ! python3 - "$FILE" "$OUT/decide.yml" "$ROOT/roles/synapse/defaults/main.yml" <<'PY'
import sys, yaml
tasks = yaml.safe_load(open(sys.argv[1]))
found = [t for t in tasks if t.get("name") == "Decide whether the package index needs refreshing"]
refresh = [t for t in tasks if t.get("name") == "Refresh the package index for the new source"]
if len(found) != 1 or len(refresh) != 1 or "synapse_apt_refresh_needed" not in str(refresh[0].get("when")):
    print("FAIL: repo_debian.yml has no decision task that the refresh task uses", file=sys.stderr)
    sys.exit(1)
index = [t for t in tasks if str(t.get("name", "")).startswith("Look for the fetched package index")]
yaml.safe_dump([{"hosts": "localhost", "connection": "local", "gather_facts": False,
                 "vars_files": [sys.argv[3]],
                 "tasks": index + found + [{"ansible.builtin.copy": {"dest": "{{ out }}", "mode": "0600",
                                    "content": "{{ synapse_apt_refresh_needed | bool }}"}}]}],
               open(sys.argv[2], "w"))
PY
then
  echo "FAIL: no decision task"; exit 1
fi

rc=0
check() { # name credential keyring source expected [index file name in the lists directory]
  rm -f "$OUT/res"
  rm -rf "$OUT/lists"; mkdir "$OUT/lists"
  # Unrelated indexes are always there: only the Gen0Sec one may count.
  : > "$OUT/lists/archive.ubuntu.com_ubuntu_dists_focal_InRelease"
  [ -n "${6:-}" ] && : > "$OUT/lists/$6"
  ANSIBLE_BECOME=False ANSIBLE_LOCALHOST_WARNING=False ANSIBLE_NOCOLOR=1 \
    ansible-playbook -i localhost, "$OUT/decide.yml" -e "out=$OUT/res" -e "synapse_apt_lists_dir=$OUT/lists" -e "{
      \"synapse_apt_credential\": {\"changed\": $2},
      \"synapse_keyring_write\": $3,
      \"synapse_apt_source\": {\"changed\": $4}}" > "$OUT/log" 2>&1
  local got; got="$(cat "$OUT/res" 2>/dev/null)"
  if [ "$got" = "$5" ]; then echo "ok   $1: refresh=$5"; else
    echo "FAIL $1: expected refresh=$5, got '${got:-no result}'"; tail -4 "$OUT/log"; rc=1
  fi
}
SKIPPED='{"changed": false, "skipped": true}'
IDX=apt.gen0sec.com_dists_stable_InRelease
check nothing_changed        false "$SKIPPED"            false False "$IDX"
check keyring_unchanged_run  false '{"changed": false}'  false False "$IDX"
check index_is_Release_file  false "$SKIPPED"            false False apt.gen0sec.com_dists_stable_Release
check index_missing          false "$SKIPPED"            false True
check index_of_other_suite   false "$SKIPPED"            false True  apt.gen0sec.com_dists_beta_InRelease
check index_of_other_repo    false "$SKIPPED"            false True  archive.ubuntu.com_ubuntu_dists_stable_InRelease
check credential_only        true  "$SKIPPED"            false True "$IDX"
check keyring_only           false '{"changed": true}'   false True "$IDX"
check source_only            false "$SKIPPED"            true  True "$IDX"
check all_changed            true  '{"changed": true}'   true  True "$IDX"
exit "$rc"
