#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, iacforge contributors
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: snowflake_grant
short_description: Grant or revoke Snowflake privileges to a role
author:
  - iacforge contributors (@iacforge)
description:
  - Compares requested privileges with C(SHOW GRANTS TO ROLE) / C(SHOW FUTURE GRANTS IN SCHEMA)
    and only grants or revokes what differs.
  - For C(all_*_in_schema) every existing object is checked; the bulk GRANT runs only if one is missing.
options:
  privileges:
    description: Explicit privileges such as V(USAGE), V(SELECT), V(EXECUTE ALERT). V(ALL) is rejected because it cannot be compared.
    type: list
    elements: str
    required: true
  object_type:
    description: Securable object type.
    type: str
    required: true
    choices: [account, warehouse, database, schema, table, view,
              all_tables_in_schema, all_views_in_schema, future_tables_in_schema, future_views_in_schema]
  object_name:
    description: Object name. V(DB.SCHEMA) for schema-level types, V(DB.SCHEMA.OBJECT) for table/view. Not used for V(account).
    type: str
  to_role:
    description: Grantee role.
    type: str
    required: true
  state:
    description: Grant (present) or revoke (absent) the privileges.
    type: str
    choices: [present, absent]
    default: present
extends_documentation_fragment:
  - iacforge.snowflake_iac.connection
"""

EXAMPLES = r"""
- name: Reader can use the warehouse
  iacforge.snowflake_iac.snowflake_grant:
    privileges: [USAGE]
    object_type: warehouse
    object_name: WH_PLATFORM_DEV
    to_role: PLATFORM_READER
    role: SECURITYADMIN

- name: Reader sees every future view in ANALYTICS
  iacforge.snowflake_iac.snowflake_grant:
    privileges: [SELECT]
    object_type: future_views_in_schema
    object_name: TASTY_BYTES_DEMO.ANALYTICS
    to_role: PLATFORM_READER
"""

RETURN = r"""
statements:
  description: SQL executed (or that would be executed in check mode).
  returned: always
  type: list
  elements: str
"""

import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.iacforge.snowflake_iac.plugins.module_utils.snowflake_common import (
    KEY_REQUIRED_ONE_OF, connection_argument_spec, fetch_dicts, ident, qualified, run_plan, show_one,
)

PRIVILEGE_RE = re.compile(r"^[A-Z][A-Z ]*[A-Z]$")

# on -> (name parts, SQL target template, granted_on value, kind of check)
TARGETS = {
    "account": (0, "ACCOUNT", "ACCOUNT", "direct"),
    "warehouse": (1, "WAREHOUSE {n}", "WAREHOUSE", "direct"),
    "database": (1, "DATABASE {n}", "DATABASE", "direct"),
    "schema": (2, "SCHEMA {n}", "SCHEMA", "direct"),
    "table": (3, "TABLE {n}", "TABLE", "direct"),
    "view": (3, "VIEW {n}", "VIEW", "direct"),
    "all_tables_in_schema": (2, "ALL TABLES IN SCHEMA {n}", "TABLE", "all"),
    "all_views_in_schema": (2, "ALL VIEWS IN SCHEMA {n}", "VIEW", "all"),
    "future_tables_in_schema": (2, "FUTURE TABLES IN SCHEMA {n}", "TABLE", "future"),
    "future_views_in_schema": (2, "FUTURE VIEWS IN SCHEMA {n}", "VIEW", "future"),
}


def clean_name(value):
    return str(value).replace('"', "").upper()


def normalize_privileges(values):
    out = []
    for value in values:
        priv = " ".join(str(value).upper().split())
        if priv in ("ALL", "ALL PRIVILEGES"):
            raise ValueError("Use explicit privileges instead of ALL so grants can be compared")
        if not PRIVILEGE_RE.match(priv):
            raise ValueError("Invalid privilege: %r" % value)
        out.append(priv)
    return out


def object_name(p):
    parts = TARGETS[p["object_type"]][0]
    if parts == 0:
        return ""
    if not p.get("object_name"):
        raise ValueError("object_name is required for object_type=%s" % p["object_type"])
    return ident(p["object_name"]) if parts == 1 else qualified(p["object_name"], parts)


def build_statements(p, current):
    """current = {'grants': {(priv, granted_on, name)}, 'objects': [names], 'future': {(priv, granted_on)}}"""
    privileges = normalize_privileges(p["privileges"])
    role = ident(p["to_role"], "role")
    name = object_name(p)
    unused_parts, template, granted_on, kind = TARGETS[p["object_type"]]
    target = template.format(n=name)
    present = p["state"] == "present"

    if kind == "direct":
        key_name = "*" if p["object_type"] == "account" else name
        have = {priv for priv in privileges if (priv, granted_on, key_name) in current["grants"]}
    elif kind == "future":
        have = {priv for priv in privileges if (priv, granted_on) in current["future"]}
    else:
        objects = ["%s.%s" % (name, clean_name(o)) for o in current["objects"]]
        complete = {priv for priv in privileges
                    if all((priv, granted_on, o) in current["grants"] for o in objects)}
        partial = {priv for priv in privileges
                   if any((priv, granted_on, o) in current["grants"] for o in objects)}
        have = complete if present else partial

    if present:
        missing = [priv for priv in privileges if priv not in have]
        return ["GRANT %s ON %s TO ROLE %s" % (", ".join(missing), target, role)] if missing else []
    extra = [priv for priv in privileges if priv in have]
    return ["REVOKE %s ON %s FROM ROLE %s" % (", ".join(extra), target, role)] if extra else []


def gather(cur, p):
    role = ident(p["to_role"], "role")
    unused_parts, unused_template, granted_on, kind = TARGETS[p["object_type"]]
    current = {"grants": set(), "objects": [], "future": set()}

    # A missing grantee (or schema) means nothing is granted yet - typical in --check
    # before the role/schema is created. Outside check mode the GRANT itself reports the error.
    if not show_one(cur, "ROLES", role):
        return current

    if kind == "future":
        try:
            rows = fetch_dicts(cur, "SHOW FUTURE GRANTS IN SCHEMA %s" % object_name(p))
        except Exception as exc:
            if "does not exist" in str(exc):
                return current
            raise
        for row in rows:
            if clean_name(row.get("grantee_name")) == role:
                current["future"].add((str(row["privilege"]).upper(), str(row["grant_on"]).upper()))
        return current

    for row in fetch_dicts(cur, "SHOW GRANTS TO ROLE %s" % role):
        on = str(row.get("granted_on", "")).upper()
        name = "*" if on == "ACCOUNT" else clean_name(row.get("name"))
        current["grants"].add((str(row["privilege"]).upper(), on, name))

    if kind == "all":
        listing = "TABLES" if granted_on == "TABLE" else "VIEWS"
        try:
            current["objects"] = [r["name"] for r in fetch_dicts(cur, "SHOW %s IN SCHEMA %s" % (listing, object_name(p)))]
        except Exception as exc:
            if "does not exist" not in str(exc):
                raise
    return current


def main():
    argument_spec = connection_argument_spec()
    argument_spec.update(
        privileges=dict(type="list", elements="str", required=True),
        object_type=dict(type="str", required=True, choices=list(TARGETS)),
        object_name=dict(type="str"),
        to_role=dict(type="str", required=True),
        state=dict(type="str", default="present", choices=["present", "absent"]),
    )
    module = AnsibleModule(argument_spec=argument_spec, required_one_of=KEY_REQUIRED_ONE_OF, supports_check_mode=True)
    run_plan(module, lambda cur: build_statements(module.params, gather(cur, module.params)))


if __name__ == "__main__":
    main()
