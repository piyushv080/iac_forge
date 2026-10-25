# Changelog

All notable changes to `iacforge.snowflake_iac` are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## 0.1.0 - initial release

### Modules
- `snowflake_warehouse` - create, alter, drop, suspend, resume warehouses
- `snowflake_database` - databases and schemas
- `snowflake_role` - roles and role hierarchy
- `snowflake_grant` - privileges on account, warehouse, database, schema, table, view, ALL / FUTURE in schema
- `snowflake_user` - users, RSA key slots compared by fingerprint, role grants with movers support
- `snowflake_resource_monitor` - credit quotas, triggers, account assignment
- `snowflake_query` - SQL text or statements, returns rows, `read_only` mode
- `snowflake_keypair` - encrypted RSA key pair generation

### Event source
- `snowflake_events` - Event-Driven Ansible source polling a Snowflake events table

### Notes
- Desired-state modules read current state first: accurate `changed`, full `--check` support.
- Identifiers are validated to prevent SQL injection.
- Tested against a live Snowflake account (create, idempotent re-run, drift correction, key rotation).
