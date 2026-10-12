# Fail2Ban Role

This role configures Fail2Ban to report bans to the Gen0Sec Signal API (v2).

## Role Variables

- `fail2ban_enabled`: Enable Fail2Ban integration (default: `false`). When `true`, `gen0sec_api_key` must be set, or the run fails.
- `gen0sec_api_key`: Gen0Sec API key (used for both synapse and fail2ban). `g0s_api_key` is accepted as a legacy alias.
- `gen0sec_expiration`: Block expiration time in seconds (default: empty, which uses the jail's `bantime`)
- `fail2ban_host`: This host's part of the rule name (default: empty, which uses the short hostname)
- `fail2ban_jail_enabled`: Enable fail2ban jails (default: `true`)
- `fail2ban_backend`: Fail2Ban backend (default: `systemd`)
- `fail2ban_manage_service`: Install the packages and manage the service (default: `true`). Used by `test/fail2ban_render.sh`.
- `fail2ban_config_dir`, `fail2ban_file_owner`, `fail2ban_file_group`: Where the files go and who owns them (defaults: `/etc/fail2ban`, `root`, `root`). Change them only to render into a scratch directory: the action reads the key from `/etc/fail2ban/gen0sec.headers`.

## What This Role Does

1. Installs fail2ban, curl and jq
2. Installs the Gen0Sec action to `/etc/fail2ban/action.d/gen0sec.conf` (`files/gen0sec.conf`, kept identical to the action in the public example repository)
3. Writes the API key to `/etc/fail2ban/gen0sec.headers` as `Authorization: Bearer <key>` (root:root, mode 0600). The action passes the file to curl, so the key never appears in the command Fail2Ban runs and logs.
4. Writes `/etc/fail2ban/action.d/gen0sec.local` with the `[Init]` keys `expiration` and `g0shost`, only when `gen0sec_expiration` or `fail2ban_host` is set, and removes it when neither is
5. Configures jail.local with Gen0Sec integration
6. Enables and starts the fail2ban service, and restarts it through a handler only when a file changed

The header file task runs with `no_log` and without a diff, so the key does not appear in Ansible output.

## Upgrading from the earlier role

The earlier role templated the key into `gen0sec.conf`. The key now lives only in the header file, and a role run replaces the old `gen0sec.conf`. The default expiration changed from 600 seconds to the jail's `bantime`; set `gen0sec_expiration` to keep 600.

## Usage

Include in a playbook:

```yaml
- hosts: all
  roles:
    - role: fail2ban
      vars:
        fail2ban_enabled: true
        gen0sec_api_key: "your_key"
```

Or conditionally:

```yaml
- hosts: all
  roles:
    - role: fail2ban
      when: fail2ban_enabled | bool
```

## Tests

- `python3 test/fail2ban_action.py` runs the action's commands, rendered by Fail2Ban, against a mock of the API.
- `bash test/fail2ban_render.sh` runs this role into a scratch directory and checks the header file, the overrides, the empty-key failure, that the key stays out of the output, and that a second run changes nothing.
