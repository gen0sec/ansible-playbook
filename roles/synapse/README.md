# Synapse Role

This role installs Synapse from the Gen0Sec package repositories and configures it.

## Role Variables

- `gen0sec_repo_key`: repository key (default: `GEN0SEC_REPO_KEY` from the control machine's environment). Required.
- `synapse_config_mode`: `agent` (default) or `proxy`.
- `synapse_ml`: install the `-ml` package (default: `false`)
- `synapse_version`: `""` for the repository's current version, or a pin such as `0.9.0` or `0.9.0~rc.1`
- `synapse_package_state`: `present` (default) or `latest`
- `synapse_service_state`: `started` (default) or `stopped`
- `synapse_apt_url`, `synapse_rpm_url`, `synapse_apt_suite`, `synapse_apt_component`, `synapse_apt_keyring`, `synapse_keyserver_url`, `synapse_repo_key_fingerprint`: repository and signing key settings
- `gen0sec_api_key`: Gen0Sec API key to set in config.yaml (optional)
- `clamav_enabled`: Enable ClamAV installation and configuration (default: `true`)
- `redis_enabled`: Enable Redis installation (default: `true`)

## What This Role Does

1. Checks the OS (Debian family, or RHEL family with dnf), the key and the variables, and picks the package
2. Removes a legacy `synapse.service` that matches the old role exactly
3. Sets up the APT or DNF repository with the key in a root-only file, and verifies the signing key fingerprint
4. Installs dependencies (curl, sed), and optionally ClamAV and Redis
5. Removes the other three Synapse packages and installs the chosen one
6. Renders `/etc/synapse/config.yaml` (0640) and validates it with `synapse --check-config` when supported
7. Restarts on a config change, then enables and starts the unit named after the package

Secret files are re-checked to be root-only on every run, and tasks that handle
the key use `no_log` and `diff: false`.

## Usage

```yaml
- hosts: all
  roles:
    - synapse
```

With variables (keep the repository key in the environment or a vault):

```yaml
- hosts: all
  roles:
    - role: synapse
      vars:
        synapse_config_mode: proxy
        synapse_version: "0.9.0"
```
