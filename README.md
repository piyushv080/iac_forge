# iacforge.snowflake_iac

Snowflake **infrastructure as code** for Ansible: idempotent modules for warehouses, databases, roles, grants,
users, key-pair authentication and rotation, resource monitors and SQL - plus an Event-Driven Ansible
event source for self-healing.

- Reads current state first, so `changed` is accurate and **re-runs report `changed=0`**
- Full **`--check`** support: shows the exact SQL that would run
- **Key-pair auth only**, keys compared by fingerprint, zero-downtime rotation via the two key slots
- Identifiers validated to **prevent SQL injection**
- Works in **AWX / Ansible Automation Platform** execution environments

## Install

```bash
ansible-galaxy collection install iacforge.snowflake_iac
pip install snowflake-connector-python cryptography
```

Or in `collections/requirements.yml`:

```yaml
collections:
  - name: iacforge.snowflake_iac
    version: ">=0.1.0"
```

## Modules

| Module | Purpose |
|--------|---------|
| `snowflake_warehouse` | create / alter / drop / suspend / resume warehouses |
| `snowflake_database` | databases and their schemas |
| `snowflake_role` | roles and role hierarchy |
| `snowflake_grant` | privileges on account, warehouse, database, schema, table, view, ALL / FUTURE in schema |
| `snowflake_user` | users, RSA key slots, role grants (movers via `roles_scope`) |
| `snowflake_resource_monitor` | credit quotas, triggers, account assignment |
| `snowflake_query` | run SQL, return rows; `read_only: true` for queries in `--check` |
| `snowflake_keypair` | generate an encrypted RSA key pair |

Event source: `iacforge.snowflake_iac.snowflake_events` (polls an events table written by Snowflake alerts).

Full docs: `ansible-doc iacforge.snowflake_iac.<module>`

## Quick start

```yaml
- name: Snowflake platform
  hosts: localhost
  connection: local
  gather_facts: false
  module_defaults:
    group/iacforge.snowflake_iac.snowflake:        # connection set once for all modules
      account: myorg-myaccount
      user: SVC_PLATFORM_AUTOMATION
      private_key: "{{ vault_sf_private_key }}"
      private_key_passphrase: "{{ vault_sf_private_key_passphrase }}"
  tasks:
    - name: Resource monitor
      iacforge.snowflake_iac.snowflake_resource_monitor:
        name: RM_TEAM_A
        credit_quota: 10
        role: ACCOUNTADMIN

    - name: Warehouse
      iacforge.snowflake_iac.snowflake_warehouse:
        name: WH_TEAM_A
        size: XSMALL
        auto_suspend: 60
        resource_monitor: RM_TEAM_A
        role: SYSADMIN

    - name: Reader role sees future views
      iacforge.snowflake_iac.snowflake_grant:
        privileges: [SELECT]
        object_type: future_views_in_schema
        object_name: ANALYTICS_DB.REPORTING
        to_role: TEAM_A_READER
        role: SECURITYADMIN
```

Connection options also fall back to environment variables: `SF_ACCOUNT`, `SF_USER`, `SF_PRIVATE_KEY`,
`SF_PRIVATE_KEY_PATH`, `SF_PRIVATE_KEY_PASSPHRASE`, `SF_ROLE`, `SF_WAREHOUSE`.

### Short module names in roles

Declare the collection once in `roles/<role>/meta/main.yml`:

```yaml
collections:
  - iacforge.snowflake_iac
```

Then tasks can use `snowflake_warehouse:` instead of the full name.

## Execution environments (AWX / AAP)

The collection ships `meta/execution-environment.yml`, so `ansible-builder` installs the Snowflake driver automatically:

```yaml
# execution-environment.yml
version: 3
images:
  base_image:
    name: quay.io/ansible/awx-ee:latest
dependencies:
  galaxy:
    collections:
      - name: iacforge.snowflake_iac
```

```bash
ansible-builder build -t snowflake-ee:1.0 -f execution-environment.yml
```

Modules run on the controller / inside the EE (`connection: local`) and need outbound HTTPS to Snowflake.

## Issues and contributions

Found a bug or need a feature? Open an issue: https://github.com/piyushv080/iac_forge/issues
(remove account identifiers, keys and passphrases from anything you paste).

## Requirements

- ansible-core >= 2.15
- Python packages: `snowflake-connector-python >= 3.10`, `cryptography >= 42`

## License

GNU General Public License v3.0 or later (see [LICENSE](LICENSE)), the standard license for Ansible content.
This is a community project and is not affiliated with or endorsed by Snowflake Inc.
