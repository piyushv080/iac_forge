#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, iacforge contributors
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: snowflake_user
short_description: Manage Snowflake users, RSA key slots and role grants
author:
  - iacforge contributors (@iacforge)
description:
  - Creates, alters, disables or drops a user. Passwords are never set.
  - RSA public keys are compared by fingerprint (C(RSA_PUBLIC_KEY_FP)), so re-runs are idempotent.
  - O(roles) are granted additively; set O(roles_scope) to also revoke roles from that scope that are not listed (movers).
options:
  name:
    description: User name.
    type: str
    required: true
  state:
    description: Whether the user should exist.
    type: str
    choices: [present, absent]
    default: present
  type:
    description: User type.
    type: str
    choices: [PERSON, SERVICE, LEGACY_SERVICE]
  login_name:
    description: Login name (for example the UPN used by SSO).
    type: str
  display_name:
    description: Display name.
    type: str
  email:
    description: Email address.
    type: str
  comment:
    description: Comment on the user.
    type: str
  default_role:
    description: Default role for new sessions.
    type: str
  default_warehouse:
    description: Default warehouse for new sessions.
    type: str
  disabled:
    description: Disable (true) or enable (false) the user.
    type: bool
  rsa_public_key:
    description: Public key body or PEM for slot 1. Empty string unsets the slot.
    type: str
  rsa_public_key_2:
    description: Public key body or PEM for slot 2 (used during rotation). Empty string unsets the slot.
    type: str
  roles:
    description: Roles to grant to the user.
    type: list
    elements: str
    default: []
  roles_scope:
    description: Roles this task manages. Granted roles in this list but not in O(roles) are revoked.
    type: list
    elements: str
    default: []
extends_documentation_fragment:
  - iacforge.snowflake_iac.connection
"""

EXAMPLES = r"""
- name: Automation service user with key-pair auth
  iacforge.snowflake_iac.snowflake_user:
    name: SVC_PLATFORM_AUTOMATION
    type: SERVICE
    default_role: PLATFORM_AUTOMATION_ROLE
    rsa_public_key: "{{ keypair.public_key }}"
    roles: [PLATFORM_AUTOMATION_ROLE]
    role: SECURITYADMIN

- name: Disable a leaver
  iacforge.snowflake_iac.snowflake_user:
    name: OLD_USER
    disabled: true
"""

RETURN = r"""
statements:
  description: SQL executed (or that would be executed in check mode). Key bodies are masked.
  returned: always
  type: list
  elements: str
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.iacforge.snowflake_iac.plugins.module_utils.snowflake_common import (
    KEY_REQUIRED_ONE_OF, connection_argument_spec, fetch_dicts, ident, norm, public_key_body,
    public_key_fingerprint, run_plan, show_one, sql_string,
)

TEXT_PROPS = [("login_name", "LOGIN_NAME", True), ("display_name", "DISPLAY_NAME", False),
              ("email", "EMAIL", False), ("comment", "COMMENT", False)]
KEY_SLOTS = [("rsa_public_key", "RSA_PUBLIC_KEY"), ("rsa_public_key_2", "RSA_PUBLIC_KEY_2")]


def build_statements(p, current):
    """current = {'row': SHOW USERS row or None, 'fingerprints': {slot: fp}, 'roles': set()}"""
    name = ident(p["name"], "user")
    row = current.get("row")
    if p["state"] == "absent":
        return ["DROP USER %s" % name] if row else []

    desired = {}
    if p.get("type"):
        desired["TYPE"] = p["type"]
    for param, prop, unused_upper in TEXT_PROPS:
        if p.get(param) is not None:
            desired[prop] = sql_string(p[param])
    if p.get("default_role"):
        desired["DEFAULT_ROLE"] = ident(p["default_role"], "role")
    if p.get("default_warehouse"):
        desired["DEFAULT_WAREHOUSE"] = ident(p["default_warehouse"], "warehouse")
    if p.get("disabled") is not None:
        desired["DISABLED"] = "TRUE" if p["disabled"] else "FALSE"

    statements = []
    if not row:
        for param, slot in KEY_SLOTS:
            if p.get(param):
                desired[slot] = sql_string(public_key_body(p[param]))
        props = " ".join("%s = %s" % kv for kv in desired.items())
        statements.append(("CREATE USER %s %s" % (name, props)).strip())
        granted = set()
    else:
        changes = []
        if "TYPE" in desired and "type" in row and norm(row["type"]).upper() != p["type"]:
            changes.append("TYPE = %s" % p["type"])
        for param, prop, upper in TEXT_PROPS:
            if prop in desired:
                have = norm(row.get(param))
                want = p[param]
                if (have.upper() != want.upper()) if upper else (have != want):
                    changes.append("%s = %s" % (prop, desired[prop]))
        for prop, col in (("DEFAULT_ROLE", "default_role"), ("DEFAULT_WAREHOUSE", "default_warehouse")):
            if prop in desired and norm(row.get(col)).upper() != desired[prop]:
                changes.append("%s = %s" % (prop, desired[prop]))
        if "DISABLED" in desired and (norm(row.get("disabled")).lower() == "true") != p["disabled"]:
            changes.append("DISABLED = %s" % desired["DISABLED"])
        if changes:
            statements.append("ALTER USER %s SET %s" % (name, " ".join(changes)))

        for param, slot in KEY_SLOTS:
            want = p.get(param)
            if want is None:
                continue
            have_fp = current["fingerprints"].get(slot)
            if want == "":
                if have_fp:
                    statements.append("ALTER USER %s UNSET %s" % (name, slot))
            elif public_key_fingerprint(want) != have_fp:
                statements.append("ALTER USER %s SET %s = %s" % (name, slot, sql_string(public_key_body(want))))
        granted = current["roles"]

    wanted_roles = [ident(r, "role") for r in p.get("roles") or []]
    for role in wanted_roles:
        if role not in granted:
            statements.append("GRANT ROLE %s TO USER %s" % (role, name))
    scope = {ident(r, "role") for r in p.get("roles_scope") or []}
    for role in sorted((granted & scope) - set(wanted_roles)):
        statements.append("REVOKE ROLE %s FROM USER %s" % (role, name))
    return statements


def gather(cur, name):
    current = {"row": show_one(cur, "USERS", name), "fingerprints": {}, "roles": set()}
    if current["row"]:
        for prop in fetch_dicts(cur, "DESC USER %s" % name):
            key = str(prop.get("property", "")).upper()
            if key in ("RSA_PUBLIC_KEY_FP", "RSA_PUBLIC_KEY_2_FP"):
                current["fingerprints"][key[:-3]] = norm(prop.get("value")) or None
        current["roles"] = {str(r["role"]).upper() for r in fetch_dicts(cur, "SHOW GRANTS TO USER %s" % name)}
    return current


def mask(statement):
    for unused_param, slot in KEY_SLOTS:
        marker = "%s = '" % slot
        if marker in statement:
            head, tail = statement.split(marker, 1)
            statement = head + marker + "***'" + tail.split("'", 1)[1]
    return statement


def main():
    argument_spec = connection_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=True),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        type=dict(type="str", choices=["PERSON", "SERVICE", "LEGACY_SERVICE"]),
        login_name=dict(type="str"),
        display_name=dict(type="str"),
        email=dict(type="str"),
        comment=dict(type="str"),
        default_role=dict(type="str"),
        default_warehouse=dict(type="str"),
        disabled=dict(type="bool"),
        rsa_public_key=dict(type="str", no_log=False),
        rsa_public_key_2=dict(type="str", no_log=False),
        roles=dict(type="list", elements="str", default=[]),
        roles_scope=dict(type="list", elements="str", default=[]),
    )
    module = AnsibleModule(argument_spec=argument_spec, required_one_of=KEY_REQUIRED_ONE_OF, supports_check_mode=True)

    executed = []

    def plan(cur):
        statements = build_statements(module.params, gather(cur, ident(module.params["name"], "user")))
        executed.extend(statements)
        return statements

    # Wrap exit_json so returned statements never contain full key bodies.
    original_exit = module.exit_json

    def masked_exit(**kwargs):
        kwargs["statements"] = [mask(s) for s in kwargs.get("statements", [])]
        original_exit(**kwargs)

    module.exit_json = masked_exit
    run_plan(module, plan)


if __name__ == "__main__":
    main()
