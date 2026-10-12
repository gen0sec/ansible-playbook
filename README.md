# Synapse Ansible playbook

Ansible playbook and roles to deploy [Synapse](https://gen0sec.com) in agent or proxy mode.

Synapse is installed from the Gen0Sec package repositories (APT on
Debian/Ubuntu, DNF on RHEL-family), signed and authenticated with a repository
key. Both the repository and the package signature are verified.

## Layout

- `playbook.yml`: the main playbook.
- `roles/synapse/`: repository setup, package install, host preparation and `config.yaml` rendering.
- `roles/fail2ban/`: optional Fail2Ban integration with the Gen0Sec API.
- `group_vars/all_example.yml`, `hosts.example`: starting points for your variables and inventory.
- `test/`: tests that run without a Synapse binary.

## Requirements

- Ansible (`ansible-core`) on the control machine.
- SSH access to the target hosts with sudo privileges.
- Targets: Debian/Ubuntu, or RHEL-family Linux version 8 or newer with `dnf`.
  EL7 and `yum` are not supported and the play stops with a message.
- A Gen0Sec repository key (dashboard: Clients -> Repository Access).

## Quick start

```bash
cp hosts.example hosts                       # add your servers
mkdir -p group_vars
cp group_vars/all_example.yml group_vars/all.yml   # set variables
export GEN0SEC_REPO_KEY=...                  # the repository key
ansible-playbook playbook.yml
```

The repository key is read from the `GEN0SEC_REPO_KEY` environment variable of
the control machine, so it is not written to a file or an argument list. You can
also set `gen0sec_repo_key` in an Ansible Vault file. Do not pass it with `-e`:
that puts it in the process list. The key is written only to a root-only file on
the target (`/etc/apt/auth.conf.d/gen0sec.conf` or `/etc/yum.repos.d/gen0sec.repo`,
mode 0600) and never appears in task output or diffs.

The Gen0Sec API key is optional. Get one from
<https://dash.gen0sec.com/settings/api-keys> and pass it with
`-e gen0sec_api_key=...`. `group_vars/all.yml` does not yet override the keys
fixed in `playbook.yml` (see Variables); use `-e` for those.

## What is installed

One of four mutually exclusive packages, chosen by mode and `synapse_ml`:

| `synapse_config_mode` | `synapse_ml: false` | `synapse_ml: true` |
| --- | --- | --- |
| `agent` (default) | `synapse-agent` | `synapse-agent-ml` |
| `proxy` | `synapse-proxy` | `synapse-proxy-ml` |

The systemd unit is named after the package. Changing mode or `synapse_ml`
removes the other three packages first, so a re-run switches cleanly.
`/etc/synapse/config.yaml` (root, mode 0640) is generated from the role template and
validated with `synapse --check-config` when the installed binary supports it;
otherwise the play prints a notice and skips that check.

## Variables

Fixed in the `vars:` of `playbook.yml` for now, so group_vars and the inventory
cannot override them and `-e` (for example `-e fail2ban_enabled=false`) is the
only override until a follow-up removes them: `clamav_enabled`, `redis_enabled`,
`fail2ban_enabled` (set to `true` there), `gen0sec_expiration`,
`fail2ban_jail_enabled`, `fail2ban_backend`.

Settable through group_vars, the inventory or `-e`:

- `gen0sec_repo_key`: repository key (default: `GEN0SEC_REPO_KEY` from the environment). Required.
- `synapse_config_mode`: `agent` (default) or `proxy`.
- `synapse_ml`: install the `-ml` package with the bundled models (default `false`).
- `synapse_version`: `""` installs what the repository serves; `0.9.0` or `0.9.0~rc.1` pins it (package release `-1`). A pin needs `synapse_package_state: present`.
- `synapse_package_state`: `present` (default) or `latest`.
- `synapse_service_state`: `started` (default) or `stopped`; the unit is always enabled.
- `synapse_apt_url`, `synapse_rpm_url`, `synapse_apt_suite`, `synapse_apt_component`, `synapse_apt_keyring`, `synapse_keyserver_url`, `synapse_repo_key_fingerprint`: repository location and signing key; the defaults point at the Gen0Sec repositories. The key is fetched and its fingerprint is checked before it is trusted.
- `gen0sec_api_key`: Gen0Sec API key, used by Synapse and Fail2Ban (optional).
- `synapse_config_*`: map to `config.yaml` settings; see `roles/synapse/defaults/main.yml` and `roles/synapse/templates/config.yaml.j2`.

## Migrating from the earlier role

A host with an old `/etc/systemd/system/synapse.service` that runs
`/usr/local/bin/synapse --daemon --config /etc/synapse/config.yaml` has it
stopped, disabled and removed on the first run, because the packaged unit
replaces it. A unit that differs is left alone with a warning. A binary at
`/usr/local/bin/synapse` is never deleted; the play warns so you can remove it.

## Development

```bash
make help      # list the targets
make install   # ansible-core, ansible-lint, yamllint
make lint      # yamllint and ansible-lint
make build     # playbook syntax check
make test      # tests that need no Synapse binary, network or root
GEN0SEC_REPO_KEY=... make test-install DISTRO=ubuntu MODE=agent   # needs docker
```

`make test-install` (`DISTRO=ubuntu|oracle`, `MODE=agent|proxy`) installs in a
systemd container (Ubuntu 20.04 or Oracle Linux 9) and checks the package, unit,
file modes, a second run with no changes and that the key is in no other file.
Without `GEN0SEC_REPO_KEY` it prints SKIP and exits 77; it never reports a pass
it did not earn.

`make test` skips the `synapse --check-config` step when no Synapse build with
that flag is available and says so. Set `SYNAPSE_BIN` to run it.

`ansible-lint` findings that predate this repository are marked with
inline `# noqa: <rule>` comments; CI blocks new ones.

## License

Apache-2.0, see `LICENSE`.
