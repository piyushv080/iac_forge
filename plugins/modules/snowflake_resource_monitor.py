#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, iacforge contributors
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: snowflake_resource_monitor
short_description: Manage Snowflake resource monitors (credit quotas)
author:
  - iacforge contributors (@iacforge)
description:
  - Creates, alters or drops a resource monitor and optionally assigns it to the account.
  - Requires ACCOUNTADMIN.
options:
  name:
    description: Resource monitor name.
    type: str
    required: true
  state:
    description: Whether the resource monitor should exist.
    type: str
    choices: [present, absent]
    default: present
  credit_quota:
    description: Credits allowed per frequency interval (whole number).
    type: int
    default: 10
  frequency:
    description: How often the quota resets.
    type: str
    choices: [MONTHLY, DAILY, WEEKLY, YEARLY, NEVER]
    default: MONTHLY
  notify_at:
    description: Percentages that send a notification.
    type: list
    elements: int
    default: [80]
  suspend_at:
    description: Percentage that suspends assigned warehouses after running queries finish.
    type: int
    default: 100
  suspend_immediate_at:
    description: Percentage that suspends assigned warehouses and cancels running queries.
    type: int
  assign_to_account:
    description: Make this the account-level monitor.
    type: bool
    default: false
extends_documentation_fragment:
  - iacforge.snowflake_iac.connection
"""

EXAMPLES = r"""
- name: 10 credits per month for dev
  iacforge.snowflake_iac.snowflake_resource_monitor:
    name: RM_PLATFORM_DEV
    credit_quota: 10
    notify_at: [75, 90]
    suspend_at: 100
    role: ACCOUNTADMIN
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
    KEY_REQUIRED_ONE_OF, connection_argument_spec, ident, norm, run_plan, show_one,
)


def percents(value):
    return sorted(int(x) for x in re.findall(r"\d+", norm(value)))


def triggers_clause(p):
    parts = ["ON %d PERCENT DO NOTIFY" % n for n in sorted(p.get("notify_at") or [])]
    if p.get("suspend_at"):
        parts.append("ON %d PERCENT DO SUSPEND" % p["suspend_at"])
    if p.get("suspend_immediate_at"):
        parts.append("ON %d PERCENT DO SUSPEND_IMMEDIATE" % p["suspend_immediate_at"])
    return ("TRIGGERS " + " ".join(parts)) if parts else ""


def build_statements(p, current):
    name = ident(p["name"], "resource monitor")
    if p["state"] == "absent":
        return ["DROP RESOURCE MONITOR %s" % name] if current else []

    statements = []
    if not current:
        statements.append(("CREATE RESOURCE MONITOR %s WITH CREDIT_QUOTA = %d FREQUENCY = %s "
                           "START_TIMESTAMP = IMMEDIATELY %s" % (
                               name, p["credit_quota"], p["frequency"], triggers_clause(p))).strip())
    else:
        sets = []
        if float(norm(current.get("credit_quota")) or 0) != float(p["credit_quota"]):
            sets.append("CREDIT_QUOTA = %d" % p["credit_quota"])
        if norm(current.get("frequency")).upper() != p["frequency"]:
            sets.append("FREQUENCY = %s START_TIMESTAMP = IMMEDIATELY" % p["frequency"])
        if sets:
            statements.append("ALTER RESOURCE MONITOR %s SET %s" % (name, " ".join(sets)))

        same_triggers = (
            percents(current.get("notify_at")) == sorted(p.get("notify_at") or [])
            and percents(current.get("suspend_at")) == ([p["suspend_at"]] if p.get("suspend_at") else [])
            and percents(current.get("suspend_immediately_at"))
            == ([p["suspend_immediate_at"]] if p.get("suspend_immediate_at") else [])
        )
        if not same_triggers and triggers_clause(p):
            statements.append("ALTER RESOURCE MONITOR %s %s" % (name, triggers_clause(p)))

    if p.get("assign_to_account") and norm((current or {}).get("level")).upper() != "ACCOUNT":
        statements.append("ALTER ACCOUNT SET RESOURCE_MONITOR = %s" % name)
    return statements


def main():
    argument_spec = connection_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=True),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        credit_quota=dict(type="int", default=10),
        frequency=dict(type="str", default="MONTHLY", choices=["MONTHLY", "DAILY", "WEEKLY", "YEARLY", "NEVER"]),
        notify_at=dict(type="list", elements="int", default=[80]),
        suspend_at=dict(type="int", default=100),
        suspend_immediate_at=dict(type="int"),
        assign_to_account=dict(type="bool", default=False),
    )
    module = AnsibleModule(argument_spec=argument_spec, required_one_of=KEY_REQUIRED_ONE_OF, supports_check_mode=True)

    def plan(cur):
        name = ident(module.params["name"], "resource monitor")
        return build_statements(module.params, show_one(cur, "RESOURCE MONITORS", name))

    run_plan(module, plan)


if __name__ == "__main__":
    main()
