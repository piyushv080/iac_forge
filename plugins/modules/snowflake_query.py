#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, iacforge contributors
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: snowflake_query
short_description: Run SQL against Snowflake and return rows
author:
  - iacforge contributors (@iacforge)
description:
  - Executes SQL text (one or many statements) or a list of statements in one session.
  - With O(read_only=true) only SELECT/SHOW/DESC/LIST/WITH/EXPLAIN are allowed, the task reports
    C(changed=false) and it also runs in check mode (like an C(_info) module).
  - Otherwise the task reports C(changed=true) and is skipped in check mode. Prefer the
    desired-state modules for objects; use this for data loads, alerts and operational actions.
options:
  sql:
    description: SQL text; multiple statements separated by semicolons are allowed.
    type: str
  statements:
    description: List of SQL statements.
    type: list
    elements: str
  parameters:
    description: Bind parameters (C(%s) / C(%(name)s) style). Only allowed with a single statement.
    type: raw
  read_only:
    description: Only allow queries; report C(changed=false) and run in check mode.
    type: bool
    default: false
  fetch:
    description: Return rows of the last statement.
    type: bool
    default: true
  max_rows:
    description: Maximum number of rows returned in RV(rows).
    type: int
    default: 1000
extends_documentation_fragment:
  - iacforge.snowflake_iac.connection
"""

EXAMPLES = r"""
- name: Count orders (works in --check)
  iacforge.snowflake_iac.snowflake_query:
    sql: SELECT COUNT(*) AS orders FROM TASTY_BYTES_DEMO.RAW_POS.ORDER_HEADER
    read_only: true
  register: q

- name: Load demo data from a template
  iacforge.snowflake_iac.snowflake_query:
    sql: "{{ lookup('ansible.builtin.template', 'demo_data.sql.j2') }}"
    warehouse: WH_PLATFORM_DEV
"""

RETURN = r"""
rows:
  description: Rows of the last statement as dicts with lower-case keys.
  returned: when fetch is true
  type: list
  elements: dict
row_count:
  description: Number of rows returned (before max_rows truncation).
  returned: always
  type: int
query_ids:
  description: Snowflake query IDs, useful for QUERY_HISTORY lookups.
  returned: always
  type: list
  elements: str
statements:
  description: Statements executed (or skipped in check mode).
  returned: always
  type: list
  elements: str
"""

import io
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.iacforge.snowflake_iac.plugins.module_utils.snowflake_common import (
    KEY_REQUIRED_ONE_OF, check_dependencies, connect, connection_argument_spec, to_jsonable,
)

READ_ONLY_PREFIXES = ("SELECT", "SHOW", "DESC", "DESCRIBE", "LIST", "WITH", "EXPLAIN")


def split_sql(text):
    from snowflake.connector.util_text import split_statements
    out = []
    for statement, unused_is_put_get in split_statements(io.StringIO(text), remove_comments=True):
        statement = statement.strip().rstrip(";").strip()
        if statement:
            out.append(statement)
    return out


def is_read_only(statement):
    return statement.lstrip("( \n\t").upper().startswith(READ_ONLY_PREFIXES)


def main():
    argument_spec = connection_argument_spec()
    argument_spec.update(
        sql=dict(type="str"),
        statements=dict(type="list", elements="str"),
        parameters=dict(type="raw"),
        read_only=dict(type="bool", default=False),
        fetch=dict(type="bool", default=True),
        max_rows=dict(type="int", default=1000),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=KEY_REQUIRED_ONE_OF + [["sql", "statements"]],
        mutually_exclusive=[["sql", "statements"]],
        supports_check_mode=True,
    )
    check_dependencies(module)
    p = module.params

    if p["sql"] is not None:
        statements = split_sql(p["sql"])
    else:
        statements = [s.strip().rstrip(";").strip() for s in p["statements"] if s and s.strip()]
    if p["parameters"] is not None and len(statements) != 1:
        module.fail_json(msg="parameters can only be used with exactly one statement")
    if p["read_only"]:
        blocked = [s for s in statements if not is_read_only(s)]
        if blocked:
            module.fail_json(msg="read_only=true but statement is not a query: %s" % blocked[0][:120])

    result = dict(changed=not p["read_only"] and bool(statements), statements=statements,
                  rows=[], row_count=0, query_ids=[])
    if module.check_mode and not p["read_only"]:
        result["skipped_reason"] = "check mode: statements not executed"
        module.exit_json(**result)

    conn = None
    try:
        conn = connect(p)
        cur = conn.cursor()
        for index, statement in enumerate(statements, start=1):
            try:
                cur.execute(statement, p["parameters"])
            except Exception as exc:
                module.fail_json(msg="Statement %d failed: %s" % (index, exc), failed_statement=statement, **result)
            result["query_ids"].append(cur.sfqid)
        if p["fetch"] and cur.description:
            cols = [c[0].lower() for c in cur.description]
            rows = cur.fetchall()
            result["row_count"] = len(rows)
            result["rows"] = [{c: to_jsonable(v) for c, v in zip(cols, r)} for r in rows[: p["max_rows"]]]
    except Exception as exc:
        module.fail_json(msg="Snowflake error: %s" % exc, exception=traceback.format_exc(), **result)
    finally:
        if conn is not None:
            conn.close()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
