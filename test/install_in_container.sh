#!/usr/bin/env bash
# Installs Synapse from the Gen0Sec package repositories inside a systemd
# container and checks the outcome. Needs docker and network access, and a
# repository key.
#
#   GEN0SEC_REPO_KEY=... bash test/install_in_container.sh <ubuntu|oracle> <agent|proxy>
#
# Phases:
#   1. pre-seed: an old synapse.service and a credential file with mode 0644
#   1b. run with a WRONG key: it must fail at the repository, and the old unit
#      must still be there (nothing is removed before the repository works)
#   2. run again with the real key, within the hour apt trusts its index: it
#      must succeed (the corrected key must refresh the index), then
#      install the requested mode and run verify_install.sh
#   3. run again: changed=0
#   4. if mode is agent, switch to proxy (the other package replaces it) and
#      verify again
#   5. no log of the ansible runs holds the key (verify_install.sh greps the
#      whole filesystem, the logs included)
#
# Exit codes: 0 passed, 1 failed, 2 usage, 3 docker missing,
#             77 SKIPPED because GEN0SEC_REPO_KEY is not set (no false pass).
#
# The key reaches the container only through the environment (docker run -e
# NAME with no value), never as an argument.
set -u

distro="${1:-}"
mode="${2:-}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(dirname "$here")"

case "$distro" in
  ubuntu) dockerfile=Dockerfile.ubuntu2004; family=deb; unit_init=/sbin/init
          creds=/etc/apt/auth.conf.d/gen0sec.conf ;;
  oracle) dockerfile=Dockerfile.oracle9; family=rpm; unit_init=/usr/sbin/init
          creds=/etc/yum.repos.d/gen0sec.repo ;;
  *) echo "usage: $0 <ubuntu|oracle> <agent|proxy>" >&2; exit 2 ;;
esac
case "$mode" in agent|proxy) ;; *) echo "usage: $0 <ubuntu|oracle> <agent|proxy>" >&2; exit 2 ;; esac

if [ -z "${GEN0SEC_REPO_KEY:-}" ]; then
  echo "SKIP: GEN0SEC_REPO_KEY is not set. The install test needs a repository key" >&2
  echo "      (Clients -> Repository Access); nothing was run and nothing passed." >&2
  exit 77
fi
command -v docker > /dev/null || { echo "docker is not installed" >&2; exit 3; }

image="synapse-install-test:$distro"
name="synapse-install-$distro-$mode-$$"
cleanup() { docker rm -f "$name" > /dev/null 2>&1 || true; }
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
die() { echo "FAIL: $*" >&2; exit 1; }
# Everything inside the container; the key is passed by name only.
in_ct() { docker exec -e GEN0SEC_REPO_KEY "$name" "$@"; }

# The playbook: no ClamAV or Redis (they are not part of this check) and no
# fail2ban, which is tested on its own.
run_playbook() { # extra -e args...
  in_ct bash -c 'set -o pipefail; cd /work && ANSIBLE_NOCOLOR=1 ansible-playbook -i localhost, -c local playbook.yml \
      -e clamav_enabled=false -e redis_enabled=false -e fail2ban_enabled=false "$@" 2>&1 | tee -a /var/log/gen0sec-ansible.log' _ "$@"
}

step "build $image"
docker build -q -t "$image" -f "$here/$dockerfile" "$here" > /dev/null || die "image build failed"

step "start $name"
docker run -d --name "$name" --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
  "$image" "$unit_init" > /dev/null || die "container did not start"
for _ in $(seq 1 30); do
  st="$(in_ct systemctl is-system-running 2>/dev/null || true)"
  case "$st" in running|degraded) break ;; esac
  sleep 1
done
docker exec "$name" mkdir -p /work
docker cp "$repo/." "$name:/work/" || die "copy of the repository failed"
docker exec "$name" rm -rf /work/.git /work/graphify-out

step "phase 1: pre-seed an old unit and a world-readable credential file"
docker exec "$name" bash -c '
  printf "[Unit]\nDescription=old synapse\n[Service]\nExecStart=/usr/local/bin/synapse --daemon --config /etc/synapse/config.yaml\n[Install]\nWantedBy=multi-user.target\n" > /etc/systemd/system/synapse.service
  mkdir -p "$(dirname '"$creds"')"
  printf "%s\n" "[gen0sec]" "name=old" "baseurl=https://rpm.example.invalid/" "enabled=0" > '"$creds"'
  chmod 0644 '"$creds"'
  systemctl daemon-reload' || die "pre-seed failed"

step "phase 1b: a wrong key fails at the repository and removes nothing"
if out="$(docker exec -e GEN0SEC_REPO_KEY=not-a-real-key-0000 "$name" bash -c 'set -o pipefail; cd /work && ANSIBLE_NOCOLOR=1 ansible-playbook -i localhost, -c local playbook.yml \
    -e clamav_enabled=false -e redis_enabled=false -e fail2ban_enabled=false -e synapse_config_mode='"$mode"' 2>&1 | tee -a /var/log/gen0sec-ansible.log')"; then
  die "a run with a wrong key succeeded"
fi
# Any failure would do for the check above, and a failure earlier on (in the
# selection of the repository, or the install of gnupg) would leave phase 2
# with a host that never reached the half-configured state it is meant to
# recover from. So the failure must be the refresh of the index, refused with
# a 401.
refresh_task="Refresh the package index for the new source"
[ "$family" = rpm ] && refresh_task="Refresh the Gen0Sec repository metadata"
failed="$(awk '/^TASK \[/ {task=$0} /^fatal: / && !/\.\.\.ignoring/ {print task " || " $0; exit}' <<< "$out")"
case "$failed" in
  *"$refresh_task"*"||"*401*) ;;
  *) echo "$out" | tail -n 15; die "the wrong-key run did not fail at \"$refresh_task\" with a 401: ${failed:-no failed task found}" ;;
esac
in_ct test -e /etc/systemd/system/synapse.service || die "the wrong-key run removed the old synapse.service"
echo "ok   the wrong key failed at \"$refresh_task\" with a 401 and the old unit is still there"

step "phase 2: install $mode with the real key (recovery after the wrong one)"
run_playbook -e synapse_config_mode="$mode" || die "first run failed (see the output above)"
in_ct test ! -e /etc/systemd/system/synapse.service || die "the old synapse.service was not removed"
in_ct /work/test/verify_install.sh "synapse-$mode" "$family" || die "verification after the first run failed"

step "phase 3: second run changes nothing"
out="$(run_playbook -e synapse_config_mode="$mode")" || { echo "$out"; die "second run failed"; }
echo "$out" | /usr/bin/grep -E '^localhost +:' || true
echo "$out" | /usr/bin/grep -Eq 'changed=0 ' || { echo "$out" | /usr/bin/grep -E '^(changed|TASK)' | tail -n 20; die "second run was not idempotent"; }

if [ "$mode" = agent ]; then
  step "phase 4: switch to proxy"
  run_playbook -e synapse_config_mode=proxy || die "proxy run failed"
  in_ct /work/test/verify_install.sh synapse-proxy "$family" || die "verification after the proxy run failed"
fi

step "phase 5: no ansible log holds the key"
# shellcheck disable=SC2016  # $GEN0SEC_REPO_KEY expands inside the container
if in_ct bash -c 'grep -qF -f <(printf "%s" "$GEN0SEC_REPO_KEY") /var/log/gen0sec-ansible.log'; then
  die "the key is in the ansible log"
fi
echo "ok   the ansible log is free of the key"

echo; echo "PASS: $distro $mode"
