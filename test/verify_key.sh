#!/usr/bin/env bash
# Checks the signing-key verification both package families share
# (tasks/verify_key.yml and tasks/fetch_key.yml), with local keys and no
# network: a key file with exactly one primary key equal to the pinned
# fingerprint passes, and anything else fails. In particular a download that
# carries TWO keys, the pinned one and another, must be refused, which a check
# of the first fingerprint line alone would accept.
#
# The keys are throwaway ones made in a temporary GNUPGHOME. The download is a
# file:// URL, so the real get_url and verify tasks run. Needs gpg and
# ansible-playbook; no root.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for c in gpg ansible-playbook; do
  command -v "$c" >/dev/null 2>&1 || { echo "FAIL: $c not found" >&2; exit 1; }
done
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
export GNUPGHOME="$OUT/gnupg"
mkdir -m 0700 "$GNUPGHOME"

mkkey() { # name -> sets fpr_<name>, writes $OUT/<name>.asc
  gpg --batch --quiet --passphrase '' --quick-generate-key "$1 <$1@example.invalid>" rsa2048 sign never 2>/dev/null
  gpg --batch --armor --export "$1@example.invalid" > "$OUT/$1.asc"
  gpg --batch --with-colons --fingerprint "$1@example.invalid" 2>/dev/null | awk -F: '/^fpr:/ {print $10; exit}'
}
PIN="$(mkkey pinned)"
OTHER="$(mkkey other)"
cat "$OUT/pinned.asc" "$OUT/other.asc" > "$OUT/two.asc"
cat "$OUT/other.asc" "$OUT/pinned.asc" > "$OUT/two_reversed.asc"
gpg --batch --dearmor < "$OUT/pinned.asc" > "$OUT/pinned.gpg"
: > "$OUT/empty.asc"
if [ -z "$PIN" ] || [ -z "$OTHER" ]; then echo "FAIL: could not make test keys" >&2; exit 1; fi

cat > "$OUT/verify.yml" <<'PLAY'
- hosts: localhost
  connection: local
  gather_facts: false
  vars_files:
    - "{{ role_dir }}/defaults/main.yml"
  tasks:
    - ansible.builtin.include_tasks: "{{ role_dir }}/tasks/verify_key.yml"
      vars:
        synapse_key_file: "{{ key_file }}"
        synapse_key_fatal: "{{ fatal | bool }}"
    - ansible.builtin.copy:
        dest: "{{ out }}"
        mode: "0600"
        content: "ok={{ synapse_key_file_ok }}\n"
PLAY

cat > "$OUT/fetch.yml" <<'PLAY'
- hosts: localhost
  connection: local
  gather_facts: false
  vars_files:
    - "{{ role_dir }}/defaults/main.yml"
  tasks:
    - ansible.builtin.include_tasks: "{{ role_dir }}/tasks/fetch_key.yml"
PLAY

rc=0
fail() { echo "FAIL $1"; rc=1; }
run() { # playbook extra-vars-json...
  local pb="$1"; shift
  ANSIBLE_BECOME=False ANSIBLE_LOCALHOST_WARNING=False ANSIBLE_NOCOLOR=1 \
    ansible-playbook -i localhost, "$OUT/$pb" -e "role_dir=$ROOT/roles/synapse" "$@" > "$OUT/log" 2>&1
}

# verify_key.yml, non-fatal: reports ok=True/False in synapse_key_file_ok.
verdict() { # name file pin expected
  rm -f "$OUT/res"
  run verify.yml -e "{\"key_file\":\"$2\",\"synapse_repo_key_fingerprint\":\"$3\",\"fatal\":false,\"out\":\"$OUT/res\"}"
  local got; got="$(tr -d '\n' < "$OUT/res" 2>/dev/null)"
  if [ "$got" = "ok=$4" ]; then echo "ok   $1: ok=$4"; else fail "$1: expected ok=$4, got '${got:-no result}'"; tail -5 "$OUT/log"; fi
}
verdict single_armored   "$OUT/pinned.asc"        "$PIN"   True
verdict single_binary    "$OUT/pinned.gpg"        "$PIN"   True
verdict lowercase_pin    "$OUT/pinned.asc"        "$(tr 'A-F' 'a-f' <<< "$PIN")" True
verdict wrong_key        "$OUT/other.asc"         "$PIN"   False
verdict two_keys         "$OUT/two.asc"           "$PIN"   False
verdict two_keys_rev     "$OUT/two_reversed.asc"  "$PIN"   False
verdict empty_file       "$OUT/empty.asc"         "$PIN"   False
verdict missing_file     "$OUT/nonexistent"       "$PIN"   False

# Fatal: a bad key stops the play, a good one does not.
fatal() { # name file expect(pass|stop)
  run verify.yml -e "{\"key_file\":\"$2\",\"synapse_repo_key_fingerprint\":\"$PIN\",\"fatal\":true,\"out\":\"$OUT/res\"}"
  local s=$?
  if [ "$3" = pass ] && [ "$s" -eq 0 ]; then echo "ok   $1: accepted"
  elif [ "$3" = stop ] && [ "$s" -ne 0 ]; then echo "ok   $1: refused"
  else fail "$1: expected $3, exit $s"; tail -5 "$OUT/log"; fi
}
fatal fatal_single "$OUT/pinned.asc" pass
fatal fatal_two    "$OUT/two.asc"    stop
fatal fatal_wrong  "$OUT/other.asc"  stop

# fetch_key.yml: the download + verify that apt and dnf both use. A download
# with two keys is refused, and the verified file is left only when good.
fetch() { # name file expect
  rm -f "$OUT/dl"
  run fetch.yml -e "{\"key_file\":\"$2\",\"synapse_repo_key_fingerprint\":\"$PIN\",\"synapse_key_download\":\"$OUT/dl\",\"synapse_key_url\":\"file://$2\"}"
  local s=$?
  if [ "$3" = pass ] && [ "$s" -eq 0 ] && [ -s "$OUT/dl" ]; then echo "ok   $1: downloaded and verified"
  elif [ "$3" = stop ] && [ "$s" -ne 0 ]; then echo "ok   $1: refused"
  else fail "$1: expected $3, exit $s"; tail -5 "$OUT/log"; fi
}
fetch fetch_single "$OUT/pinned.asc" pass
fetch fetch_two    "$OUT/two.asc"    stop
fetch fetch_wrong  "$OUT/other.asc"  stop

# The install flow of each family: the tasks "Check the installed ..." and
# "Note ..." and "Install the signing key ..." are taken out of the family file by name and run
# against a temporary keyring / key file. The block must actually write the
# file after the download check (a fact set by that check once made the block's
# own condition false half way through, so the key was downloaded, verified and
# never written), and a second run must leave it alone. Run as a normal user,
# so the owner and group (root) are dropped from the tasks.
python3 - "$ROOT" "$OUT" <<'PY'
import sys, yaml, os
root, out = sys.argv[1:]
want = {
    "repo_debian.yml": ["Check the installed keyring", "Note whether the keyring is already the signing key", "Install the signing key"],
    "repo_redhat.yml": ["Check the installed key file", "Note whether the key file is already the signing key", "Install the signing key file"],
}
for fname, names in want.items():
    tasks = yaml.safe_load(open(os.path.join(root, "roles/synapse/tasks", fname)))
    picked = [t for t in tasks if t.get("name") in names]
    assert len(picked) == 3, (fname, [t.get("name") for t in picked])
    def strip(o):
        if isinstance(o, dict):
            return {k: strip(v) for k, v in o.items() if k not in ("owner", "group")}
        if isinstance(o, list):
            return [strip(v) for v in o]
        return o
    play = [{"hosts": "localhost", "connection": "local", "gather_facts": False,
             "vars_files": [os.path.join(root, "roles/synapse/defaults/main.yml")],
             "tasks": strip(picked)}]
    d = os.path.join(out, fname.replace(".yml", "_flow"))
    os.makedirs(d, exist_ok=True)
    for helper in ("verify_key.yml", "fetch_key.yml"):
        dst = os.path.join(d, helper)
        if not os.path.exists(dst):
            os.symlink(os.path.join(root, "roles/synapse/tasks", helper), dst)
    yaml.safe_dump(play, open(os.path.join(d, "flow.yml"), "w"))
PY
flow() { # name dir keyvar (file the flow writes)
  local dest="$OUT/flow_$1.gpg"
  rm -f "$dest"
  local ev="{\"synapse_repo_key_fingerprint\":\"$PIN\",\"synapse_key_url\":\"file://$OUT/pinned.asc\",\"$3\":\"$dest\"}"
  local r1 r2
  ANSIBLE_BECOME=False ANSIBLE_LOCALHOST_WARNING=False ANSIBLE_NOCOLOR=1 \
    ansible-playbook -i localhost, "$OUT/$2/flow.yml" -e "$ev" > "$OUT/log" 2>&1; r1=$?
  if [ "$r1" -ne 0 ] || [ ! -s "$dest" ] || [ -e "$dest.download" ]; then
    fail "$1: first run: exit $r1, key file written: $([ -s "$dest" ] && echo yes || echo no), download removed: $([ -e "$dest.download" ] && echo no || echo yes)"; tail -8 "$OUT/log"; return
  fi
  if [ "$(gpg --show-keys --with-colons "$dest" 2>/dev/null | awk -F: '/^pub:/ {n++} /^fpr:/ && !f {f=$10} END {print n, f}')" != "1 $PIN" ]; then
    fail "$1: the file written is not exactly the pinned key"; return
  fi
  ANSIBLE_BECOME=False ANSIBLE_LOCALHOST_WARNING=False ANSIBLE_NOCOLOR=1 \
    ansible-playbook -i localhost, "$OUT/$2/flow.yml" -e "$ev" > "$OUT/log" 2>&1; r2=$?
  if [ "$r2" -ne 0 ] || ! grep -Eq 'changed=0 ' "$OUT/log"; then
    fail "$1: second run: exit $r2, or it changed something"; tail -8 "$OUT/log"; return
  fi
  echo "ok   $1: key written and verified, second run changes nothing"
}
flow apt_keyring_flow repo_debian_flow synapse_apt_keyring
flow rpm_keyfile_flow repo_redhat_flow synapse_rpm_key_file

# Both family files use the shared task, not a check of their own.
for f in repo_debian repo_redhat; do
  if grep -q 'fetch_key.yml' "$ROOT/roles/synapse/tasks/$f.yml"; then echo "ok   $f uses fetch_key.yml"
  else fail "$f does not use fetch_key.yml"; fi
done
exit "$rc"
