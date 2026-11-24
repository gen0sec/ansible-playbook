# Policy Role

This role applies Gen0Sec workspace policies through the management API: the
managed IDS threat classes and smart firewall rules, firewall (L3/L4) rules,
access rules, smart firewall rules and custom WAF rules. It runs on the control
machine (`policy.yml`), so the management API key never reaches the hosts.

## Role Variables

- `policy_api_key`: Management API key, read from the `GEN0SEC_MANAGEMENT_API_KEY` environment variable of the control machine. It needs `agents:read`, and read, write and delete on the rule types your policy files manage. Without it the role is skipped with a warning.
- `policy_endpoint`: API base URL (default: `GEN0SEC_ENDPOINT`, else `https://api.gen0sec.com`). HTTPS only, except for localhost.
- `policy_files`: The policy files to apply (default: `policies/*.yml` next to the playbook, sorted). One file per workspace; two files naming the same `workspace_id` are refused.
- `policy_owner_tag`: Tag marking the rules the role owns (default: `ansible`).
- `policy_prune`: Delete owned rules that are no longer in the policy file (default: `true`).
- `policy_user_agent`: User-Agent of the API requests (default: `gen0sec-policy-ansible/1.0`).

## Policy Files

Start from `policies/example.yml.example`:

| Key | What it manages |
| --- | --- |
| `workspace_id` | The workspace (required). |
| `unowned` | `keep` (default) leaves rules made in the dashboard or by other tools alone; `delete` removes them, so the workspace holds only this file. Unowned WAF rules are always kept: signal integrations write rules there too. |
| `tags` | More tags on every managed rule, next to `ansible`. |
| `batch` | How writes are sent: `auto` (default), `always` or `never` (see below). |
| `managed_ids` | Managed IDS threat classes: all on, `tiers` per class (`alert` or `block`), `default_tier` for the rest (`null` keeps each class's own default), classes in `disabled` off. Leave it out to not manage IDS classes. |
| `managed_smart_firewall` | Managed smart firewall rules: all on (`enabled`), except the ids in `excluded`. Leave it out to not manage them. |
| `firewall_rules` | L3/L4 rules, key -> rule (`name`, `direction`, `action`, `ip_version`, `protocol`, `source`, `destination`, `source_ports`, `destination_ports`, `conn_state`, `tcp_flags`, `priority`, `enabled`, `description`, `expires_at`). |
| `access_rules` | Allow or block by IP/network, ASN or country, label -> rule (`type`, `value`, `action`, `description`, `expires_at`). |
| `smart_firewall_rules` | Wirefilter rules on connections, key -> rule (`name`, `expression`, `action`, `enabled`, `order`, `description`, `expires_at`). |
| `waf_rules` | Custom WAF rules for agents in proxy mode, same fields as smart firewall rules. |

## How It Works

- **Ownership:** the role manages rules tagged `ansible`. Firewall, smart firewall and WAF rules are matched by a `[ansible:<key>]` marker at the end of their description, access rules by type and value. An owned rule changed in the dashboard is put back on the next run.
- **One change, one transaction:** all writes of a run go to the batch endpoint (`POST /management/v1/workspaces/<id>/batch`), which applies them in order, in one transaction, all or nothing. Agents receive the new policy as one configuration. Written one call at a time, every committed rule would reach the agents on its own, and an intermediate state (a drop before the allows it protects) could cut an agent off. More than 100 writes go in several batches, in order. HTTP 429 and 5xx are retried (a failed batch applied nothing); a network error is not, since the batch may have been applied. A delete of a rule that is already gone is dropped and the batch sent again.
- **`batch`:** `auto` sends single calls when the API has no batch endpoint (an older self-hosted install), allow rules before deny rules; `always` fails instead; `never` always sends single calls.
- **Concurrency:** updates and deletes carry the object's version (`If-Match`), so a concurrent change fails instead of being overwritten.
- **Dry run:** `--check --diff` lists what would be created, updated and deleted, and sends nothing.
- **Report:** per policy file, the workspace's agents, the changes and the requests sent (`sent: {"batches": n, "single": n}`).

## Usage

```bash
cp policies/example.yml.example policies/production.yml   # set workspace_id and the rules
export GEN0SEC_MANAGEMENT_API_KEY=...
ansible-playbook policy.yml --check --diff
ansible-playbook policy.yml
```

## Tests

`test/policy.sh` (part of `make test`) runs the module against an in-memory fake
of the management API (`test/fake_gen0sec_api.py`, with the batch endpoint, which
it can switch off): dry run, apply as one batch, idempotency, drift, dashboard
rules, prune, write order, the fallback without the batch endpoint,
`batch: never`, an all-or-nothing batch and duplicates (`test/policy_module.yml`);
then `policy.yml` end to end, including that the key is not printed.
