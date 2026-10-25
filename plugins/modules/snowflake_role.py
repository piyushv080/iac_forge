#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, iacforge contributors
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: snowflake_role
short_description: Manage Snowflake roles and the role hierarchy
author:
  - iacforge contributors (@iacforge)
description:
  - Creates or drops an account role and grants it to parent roles.
  - Can also be used on built-in roles (for example SYSADMIN) to grant them to another role.
options:
  name:
    description: Role name.
    type: str
    required: true
  state:
    description: Whether the role should exist.
    type: str
    choices: [present, absent]
    default: present
  comment:
    description: Comment on the role.
    type: str
  granted_to_roles:
    description: Parent roles that should be granted this role (C(GRANT ROLE name TO ROLE parent)).
    type: list
    elements: str
    default: []
  revoke_others:
    description: Revoke this role from parent roles that are not in O(granted_to_roles).
    type: bool
    default: false
extends_documentation_fragment:
  - iacforge.snowflake_iac.connection
"""

EXAMPLES = r"""
- name: Functional role rolled up to SYSADMIN
  iacforge.snowflake_iac.snowflake_role:
    name: PLATFORM_ENGINEER
    granted_to_roles: [SYSADMIN]
    role: SECURITYADMIN
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
    KEY_REQUIRED_ONE_OF, connection_argument_spec, fetch_dicts, ident, norm, run_plan, show_one, sql_string,
)


def build_statements(p, current, parent_roles):
    name = ident(p["name"], "role")
    if p["state"] == "absent":
        return ["DROP ROLE %s" % name] if current else []

    statements = []
    if not current:
        sql = "CREATE ROLE %s" % name
        if p.get("comment") is not None:
            sql += " COMMENT = %s" % sql_string(p["comment"])
        statements.append(sql)
    elif p.get("comment") is not None and norm(current.get("comment")) != p["comment"]:
        statements.append("ALTER ROLE %s SET COMMENT = %s" % (name, sql_string(p["comment"])))

    desired = [ident(r, "role") for r in p.get("granted_to_roles") or []]
    for parent in desired:
        if parent not in parent_roles:
            statements.append("GRANT ROLE %s TO ROLE %s" % (name, parent))
    if p.get("revoke_others"):
        for parent in sorted(parent_roles - set(desired)):
            statements.append("REVOKE ROLE %s FROM ROLE %s" % (name, parent))
    return statements


def main():
    argument_spec = connection_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=True),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        comment=dict(type="str"),
        granted_to_roles=dict(type="list", elements="str", default=[]),
        revoke_others=dict(type="bool", default=False),
    )
    module = AnsibleModule(argument_spec=argument_spec, required_one_of=KEY_REQUIRED_ONE_OF, supports_check_mode=True)

    def plan(cur):
        name = ident(module.params["name"], "role")
        current = show_one(cur, "ROLES", name)
        parents = set()
        if current:
            for row in fetch_dicts(cur, "SHOW GRANTS OF ROLE %s" % name):
                if str(row.get("granted_to", "")).upper() == "ROLE":
                    parents.add(str(row["grantee_name"]).upper())
        return build_statements(module.params, current, parents)

    run_plan(module, plan)


if __name__ == "__main__":
    main()
