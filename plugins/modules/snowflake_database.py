#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, iacforge contributors
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: snowflake_database
short_description: Manage Snowflake databases and their schemas
author:
  - iacforge contributors (@iacforge)
description:
  - Creates or drops a database and ensures the listed schemas exist.
  - Schemas not listed are left untouched (this module never drops schemas).
options:
  name:
    description: Database name.
    type: str
    required: true
  state:
    description: Whether the database should exist.
    type: str
    choices: [present, absent]
    default: present
  schemas:
    description: Schemas that must exist in the database.
    type: list
    elements: str
    default: []
  comment:
    description: Comment on the database.
    type: str
  data_retention_time_in_days:
    description: Time Travel retention.
    type: int
extends_documentation_fragment:
  - iacforge.snowflake_iac.connection
"""

EXAMPLES = r"""
- name: Ensure operations database with schemas
  iacforge.snowflake_iac.snowflake_database:
    name: PLATFORM_OPS
    schemas: [MONITORING, AUDIT]
    data_retention_time_in_days: 1
"""

RETURN = r"""
statements:
  description: SQL executed (or that would be executed in check mode).
  returned: always
  type: list
  elements: str
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.iacforge.snowflake_iac.plugins.module_utils.snowflake_common import (
    KEY_REQUIRED_ONE_OF, connection_argument_spec, ident, norm, run_plan, show_one, sql_string,
)


def build_statements(p, current, existing_schemas):
    name = ident(p["name"])
    if p["state"] == "absent":
        return ["DROP DATABASE %s" % name] if current else []

    statements = []
    if not current:
        sql = "CREATE DATABASE %s" % name
        if p.get("data_retention_time_in_days") is not None:
            sql += " DATA_RETENTION_TIME_IN_DAYS = %d" % p["data_retention_time_in_days"]
        if p.get("comment") is not None:
            sql += " COMMENT = %s" % sql_string(p["comment"])
        statements.append(sql)
    else:
        changes = []
        retention = p.get("data_retention_time_in_days")
        if retention is not None and int(norm(current.get("retention_time")) or 0) != retention:
            changes.append("DATA_RETENTION_TIME_IN_DAYS = %d" % retention)
        if p.get("comment") is not None and norm(current.get("comment")) != p["comment"]:
            changes.append("COMMENT = %s" % sql_string(p["comment"]))
        if changes:
            statements.append("ALTER DATABASE %s SET %s" % (name, " ".join(changes)))

    for schema in p.get("schemas") or []:
        schema = ident(schema, "schema")
        if schema not in existing_schemas:
            statements.append("CREATE SCHEMA %s.%s" % (name, schema))
    return statements


def main():
    argument_spec = connection_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=True),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        schemas=dict(type="list", elements="str", default=[]),
        comment=dict(type="str"),
        data_retention_time_in_days=dict(type="int"),
    )
    module = AnsibleModule(argument_spec=argument_spec, required_one_of=KEY_REQUIRED_ONE_OF, supports_check_mode=True)

    def plan(cur):
        name = ident(module.params["name"])
        current = show_one(cur, "DATABASES", name)
        existing = set()
        if current:
            for schema in module.params["schemas"] or []:
                schema = ident(schema, "schema")
                if show_one(cur, "SCHEMAS", schema, "DATABASE %s" % name):
                    existing.add(schema)
        return build_statements(module.params, current, existing)

    run_plan(module, plan)


if __name__ == "__main__":
    main()
