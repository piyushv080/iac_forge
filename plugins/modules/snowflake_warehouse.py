#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, iacforge contributors
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: snowflake_warehouse
short_description: Manage Snowflake virtual warehouses
author:
  - iacforge contributors (@iacforge)
description:
  - Creates, alters, drops, suspends or resumes a warehouse.
  - Reads the current state with C(SHOW WAREHOUSES) and only issues the DDL that is needed.
options:
  name:
    description: Warehouse name.
    type: str
    required: true
  state:
    description: Desired state. V(suspended)/V(resumed) also create the warehouse if it is missing.
    type: str
    choices: [present, absent, suspended, resumed]
    default: present
  size:
    description: Warehouse size, for example V(XSMALL), V(SMALL), V(MEDIUM). Defaults to V(XSMALL) on create.
    type: str
  auto_suspend:
    description: Seconds of inactivity before suspending. Defaults to 60 on create.
    type: int
  auto_resume:
    description: Resume automatically when a query arrives. Defaults to true on create.
    type: bool
  resource_monitor:
    description: Resource monitor to attach.
    type: str
  comment:
    description: Comment on the warehouse.
    type: str
extends_documentation_fragment:
  - iacforge.snowflake_iac.connection
"""

EXAMPLES = r"""
- name: Ensure an XSMALL warehouse with a monitor
  iacforge.snowflake_iac.snowflake_warehouse:
    name: WH_PLATFORM_DEV
    size: XSMALL
    auto_suspend: 60
    resource_monitor: RM_PLATFORM_DEV
    role: SYSADMIN

- name: Suspend a runaway warehouse
  iacforge.snowflake_iac.snowflake_warehouse:
    name: WH_ANALYTICS
    state: suspended
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

SIZE_ALIASES = {"XXLARGE": "2XLARGE", "XXXLARGE": "3XLARGE"}
VALID_SIZES = {"XSMALL", "SMALL", "MEDIUM", "LARGE", "XLARGE", "2XLARGE", "3XLARGE", "4XLARGE", "5XLARGE", "6XLARGE"}


def normalize_size(value):
    size = str(value).upper().replace("-", "").replace("_", "")
    return SIZE_ALIASES.get(size, size)


def build_statements(p, current):
    """Pure function: desired params + current SHOW row (or None) -> SQL statements."""
    name = ident(p["name"])
    state = p["state"]

    if state == "absent":
        return ["DROP WAREHOUSE %s" % name] if current else []

    size = normalize_size(p["size"]) if p.get("size") else None
    if size and size not in VALID_SIZES:
        raise ValueError("Unsupported warehouse size: %s" % p["size"])
    monitor = ident(p["resource_monitor"], "resource monitor") if p.get("resource_monitor") else None

    if not current:
        auto_resume = True if p.get("auto_resume") is None else p["auto_resume"]
        sql = "CREATE WAREHOUSE %s WAREHOUSE_SIZE = %s AUTO_SUSPEND = %d AUTO_RESUME = %s INITIALLY_SUSPENDED = %s" % (
            name, size or "XSMALL", 60 if p.get("auto_suspend") is None else p["auto_suspend"],
            "TRUE" if auto_resume else "FALSE", "FALSE" if state == "resumed" else "TRUE")
        if monitor:
            sql += " RESOURCE_MONITOR = %s" % monitor
        if p.get("comment") is not None:
            sql += " COMMENT = %s" % sql_string(p["comment"])
        return [sql]

    changes = []
    if size and normalize_size(current.get("size")) != size:
        changes.append("WAREHOUSE_SIZE = %s" % size)
    if p.get("auto_suspend") is not None and int(current.get("auto_suspend") or 0) != p["auto_suspend"]:
        changes.append("AUTO_SUSPEND = %d" % p["auto_suspend"])
    if p.get("auto_resume") is not None and (norm(current.get("auto_resume")).lower() == "true") != p["auto_resume"]:
        changes.append("AUTO_RESUME = %s" % ("TRUE" if p["auto_resume"] else "FALSE"))
    if monitor and norm(current.get("resource_monitor")).upper() != monitor:
        changes.append("RESOURCE_MONITOR = %s" % monitor)
    if p.get("comment") is not None and norm(current.get("comment")) != p["comment"]:
        changes.append("COMMENT = %s" % sql_string(p["comment"]))

    statements = ["ALTER WAREHOUSE %s SET %s" % (name, " ".join(changes))] if changes else []
    running = str(current.get("state", "")).upper() in ("STARTED", "RESIZING", "RESUMING")
    if state == "suspended" and running:
        statements.append("ALTER WAREHOUSE %s SUSPEND" % name)
    if state == "resumed" and not running:
        statements.append("ALTER WAREHOUSE %s RESUME IF SUSPENDED" % name)
    return statements


def main():
    argument_spec = connection_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=True),
        state=dict(type="str", default="present", choices=["present", "absent", "suspended", "resumed"]),
        size=dict(type="str"),
        auto_suspend=dict(type="int"),
        auto_resume=dict(type="bool"),
        resource_monitor=dict(type="str"),
        comment=dict(type="str"),
    )
    module = AnsibleModule(argument_spec=argument_spec, required_one_of=KEY_REQUIRED_ONE_OF, supports_check_mode=True)

    def plan(cur):
        name = ident(module.params["name"])
        return build_statements(module.params, show_one(cur, "WAREHOUSES", name))

    run_plan(module, plan)


if __name__ == "__main__":
    main()
