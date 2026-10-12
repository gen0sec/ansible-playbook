# Synapse Ansible playbook

Ansible playbook and roles to deploy [Synapse](https://gen0sec.com) in agent or proxy mode.

> **Status: not yet usable for installs.** Installation from the Gen0Sec
> package repositories is being reworked and is not in this repository yet.
> Today the roles prepare the host (ClamAV, Redis) and render
> `/etc/synapse/config.yaml`, but they do not install the Synapse package.
> A run currently fails at the last synapse task, which enables a unit that
> does not exist until the package install lands, so the Fail2Ban role is not
> reached.

## Layout

- `playbook.yml`: the main playbook.
- `roles/synapse/`: host preparation and `config.yaml` rendering.
- `roles/fail2ban/`: optional Fail2Ban integration with the Gen0Sec API.
- `group_vars/all_example.yml`, `hosts.example`: starting points for your variables and inventory.
- `test/`: tests that run without a Synapse binary.

## Requirements

- Ansible (`ansible-core`) on the control machine.
- SSH access to the target hosts with sudo privileges.
- Targets: Debian/Ubuntu or RHEL-family Linux.

## Quick start

```bash
cp hosts.example hosts                       # add your servers
mkdir -p group_vars
cp group_vars/all_example.yml group_vars/all.yml   # set variables
ansible-playbook playbook.yml
```

The Gen0Sec API key is optional. Get one from
<https://dash.gen0sec.com/settings/api-keys> and pass it with
`-e gen0sec_api_key=...`. `group_vars/all.yml` does not yet override the keys
fixed in `playbook.yml` (see Variables); use `-e` for those.

## Variables

Fixed in the `vars:` of `playbook.yml` for now, so group_vars and the inventory
cannot override them and `-e` (for example `-e fail2ban_enabled=false`) is the
only override until a follow-up removes them: `synapse_version`,
`clamav_enabled`, `redis_enabled`, `fail2ban_enabled` (set to `true` there),
`gen0sec_expiration`, `fail2ban_jail_enabled`, `fail2ban_backend`.

Settable through group_vars, the inventory or `-e`:

- `synapse_config_mode`: `agent` (default) or `proxy`.
- `gen0sec_api_key`: Gen0Sec API key, used by Synapse and Fail2Ban (optional).
- `synapse_config_*`: map to `config.yaml` settings; see `roles/synapse/defaults/main.yml` and `roles/synapse/templates/config.yaml.j2`.

## Development

```bash
make help      # list the targets
make install   # ansible-core, ansible-lint, yamllint
make lint      # yamllint and ansible-lint
make build     # playbook syntax check
make test      # tests that need no Synapse binary
```

`make test` skips the `synapse --check-config` step when no Synapse build with
that flag is available and says so. Set `SYNAPSE_BIN` to run it.

`ansible-lint` findings that predate this repository are marked with
inline `# noqa: <rule>` comments; CI blocks new ones.

## License

Apache-2.0, see `LICENSE`.
