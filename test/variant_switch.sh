#!/usr/bin/env bash
# Checks that switching package variant stops and disables the old variant's
# unit, without a repository key. The package removal does not reliably stop
# it (its maintainer script can be refused by a policy-rc.d that denies service
# actions, as in container images, or the host may not be booted with systemd
# at that moment), so the role does it. Needs docker.
#
# In the systemd test container a dummy synapse-agent.service (sleep) and a
# dummy synapse-proxy.service are started. Only roles/synapse/tasks/
# stop_other_variants.yml runs, with synapse_package=synapse-proxy. It must
# stop and disable the agent unit, leave the proxy unit running and enabled,
# not fail for the variants that have no unit, and report changed=0 on a
# second run and in --check mode once the agent is gone. A last phase covers a
# running orphan: the unit file is already gone but the process still runs.
#
# Exit codes: 0 passed, 1 failed, 3 docker missing.
set -u

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(dirname "$here")"
command -v docker > /dev/null || { echo "docker is not installed" >&2; exit 3; }

image="synapse-install-test:ubuntu"
name="synapse-variant-switch-$$"
trap 'docker rm -f "$name" > /dev/null 2>&1 || true' EXIT
die() { echo "FAIL: $*" >&2; exit 1; }
in_ct() { docker exec "$name" "$@"; }

docker build -q -t "$image" -f "$here/Dockerfile.ubuntu2004" "$here" > /dev/null || die "image build failed"
docker run -d --name "$name" --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
  "$image" /sbin/init > /dev/null || die "container did not start"
for _ in $(seq 1 30); do
  st="$(in_ct systemctl is-system-running 2>/dev/null || true)"
  case "$st" in running|degraded) break ;; esac
  sleep 1
done
docker exec "$name" mkdir -p /work/roles/synapse
docker cp "$repo/roles/synapse/tasks" "$name:/work/roles/synapse/tasks" || die "copy failed"

docker exec "$name" bash -c '
  for v in agent proxy; do
    printf "[Unit]\nDescription=dummy %s\n[Service]\nExecStart=/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n" "$v" > /etc/systemd/system/synapse-$v.service
  done
  cat > /work/play.yml <<PLAY
- hosts: localhost
  connection: local
  gather_facts: false
  vars:
    synapse_package: synapse-proxy
    synapse_conflicting_packages: [synapse-agent, synapse-agent-ml, synapse-proxy-ml]
  tasks:
    - ansible.builtin.include_tasks: roles/synapse/tasks/stop_other_variants.yml
PLAY
  systemctl daemon-reload
  systemctl enable --now synapse-agent synapse-proxy' || die "setup failed"

in_ct systemctl is-active --quiet synapse-agent || die "setup: agent unit not running"
run() { in_ct bash -c "cd /work && ANSIBLE_NOCOLOR=1 ansible-playbook -i localhost, play.yml $*" 2>&1; }

out="$(run)" || { echo "$out"; die "run failed"; }
echo "$out" | /usr/bin/grep -E 'changed='
in_ct systemctl is-active --quiet synapse-agent && die "synapse-agent is still active"
in_ct systemctl is-enabled --quiet synapse-agent && die "synapse-agent is still enabled"
in_ct systemctl is-active --quiet synapse-proxy || die "the chosen synapse-proxy was stopped"
in_ct systemctl is-enabled --quiet synapse-proxy || die "the chosen synapse-proxy was disabled"
echo "$out" | /usr/bin/grep -Eq 'changed=1 ' || die "first run did not report the stop as changed"
echo "ok   the other variant was stopped and disabled, the chosen one was left alone"

out="$(run)" || { echo "$out"; die "second run failed"; }
echo "$out" | /usr/bin/grep -Eq 'changed=0 .*failed=0' || { echo "$out"; die "second run was not idempotent"; }
echo "ok   second run changed=0"

# --check with a running variant must report the change and touch nothing.
in_ct systemctl enable --now synapse-agent > /dev/null 2>&1
out="$(run --check)" || { echo "$out"; die "check-mode run failed"; }
echo "$out" | /usr/bin/grep -Eq 'changed=1 ' || { echo "$out"; die "check mode did not report the pending stop"; }
in_ct systemctl is-active --quiet synapse-agent || die "check mode stopped the unit"
echo "ok   --check reports the change and does not stop the unit"

# A running orphan: the package is gone and so is its unit file, but the
# process lives on (what a removal under a deny policy-rc.d leaves behind).
in_ct systemctl enable --now synapse-agent > /dev/null 2>&1
in_ct systemctl is-active --quiet synapse-agent || die "orphan setup: agent unit not running"
in_ct bash -c 'systemctl disable synapse-agent > /dev/null 2>&1; rm -f /etc/systemd/system/synapse-agent.service; systemctl daemon-reload'
show="$(in_ct systemctl show --property=LoadState,ActiveState synapse-agent.service)"
echo "$show" | /usr/bin/grep -qx 'LoadState=not-found' || die "orphan setup: unit is not not-found: $show"
echo "$show" | /usr/bin/grep -Eqx 'ActiveState=(active|activating)' || die "orphan setup: unit is not running: $show"
out="$(run)" || { echo "$out"; die "orphan run failed"; }
echo "$out" | /usr/bin/grep -E 'changed='
in_ct systemctl is-active --quiet synapse-agent && die "the orphan synapse-agent is still running"
in_ct systemctl is-active --quiet synapse-proxy || die "the chosen synapse-proxy was stopped"
echo "$out" | /usr/bin/grep -Eq 'changed=1 ' || { echo "$out"; die "orphan run did not report the stop as changed"; }
echo "ok   a running orphan with no unit file was stopped"
out="$(run)" || { echo "$out"; die "second orphan run failed"; }
echo "$out" | /usr/bin/grep -Eq 'changed=0 .*failed=0' || { echo "$out"; die "second orphan run was not idempotent"; }
echo "ok   second orphan run changed=0"

echo "PASS: variant switch"
