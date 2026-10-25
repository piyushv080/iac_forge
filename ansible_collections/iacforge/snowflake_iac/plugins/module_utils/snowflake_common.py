# -*- coding: utf-8 -*-
# Copyright: (c) 2026, iacforge contributors
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared connection, safety and helper code for iacforge.snowflake_iac modules."""

import base64
import datetime
import decimal
import hashlib
import re
import traceback

from ansible.module_utils.basic import env_fallback, missing_required_lib

try:
    import snowflake.connector
    HAS_SNOWFLAKE = True
    SNOWFLAKE_IMPORT_ERROR = None
except ImportError:
    HAS_SNOWFLAKE = False
    SNOWFLAKE_IMPORT_ERROR = traceback.format_exc()

try:
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTOGRAPHY = True
    CRYPTOGRAPHY_IMPORT_ERROR = None
except ImportError:
    HAS_CRYPTOGRAPHY = False
    CRYPTOGRAPHY_IMPORT_ERROR = traceback.format_exc()

IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]{0,254}$")
QUERY_TAG = "ansible:iacforge.snowflake_iac"

# Use with AnsibleModule(required_one_of=KEY_REQUIRED_ONE_OF)
KEY_REQUIRED_ONE_OF = [["private_key", "private_key_path"]]


def connection_argument_spec():
    return dict(
        account=dict(type="str", required=True, fallback=(env_fallback, ["SF_ACCOUNT"])),
        user=dict(type="str", required=True, fallback=(env_fallback, ["SF_USER"])),
        private_key=dict(type="str", no_log=True, fallback=(env_fallback, ["SF_PRIVATE_KEY"])),
        private_key_path=dict(type="path", no_log=False, fallback=(env_fallback, ["SF_PRIVATE_KEY_PATH"])),
        private_key_passphrase=dict(type="str", no_log=True, fallback=(env_fallback, ["SF_PRIVATE_KEY_PASSPHRASE"])),
        role=dict(type="str", fallback=(env_fallback, ["SF_ROLE"])),
        warehouse=dict(type="str", fallback=(env_fallback, ["SF_WAREHOUSE"])),
    )


# ---------------------------------------------------------------- safety helpers

def ident(value, what="identifier"):
    """Validate an unquoted Snowflake identifier and return it upper-cased."""
    if not isinstance(value, str) or not IDENTIFIER_RE.match(value):
        raise ValueError("Invalid Snowflake %s: %r" % (what, value))
    return value.upper()


def qualified(value, parts, what="object name"):
    """Validate DB.SCHEMA (parts=2) or DB.SCHEMA.OBJECT (parts=3)."""
    pieces = str(value).split(".")
    if len(pieces) != parts:
        raise ValueError("%s must have %d dot-separated parts: %r" % (what, parts, value))
    return ".".join(ident(p, what) for p in pieces)


def sql_string(value):
    """Render a single-quoted SQL string literal."""
    return "'" + str(value).replace("\\", "\\\\").replace("'", "''") + "'"


def norm(value):
    """Normalise SHOW output values: None / 'null' / '' -> ''."""
    if value is None:
        return ""
    text = str(value)
    return "" if text.lower() == "null" else text


# ---------------------------------------------------------------- key helpers

def public_key_body(text):
    """Strip PEM armour and whitespace from a public key."""
    lines = [line.strip() for line in str(text).splitlines() if line.strip() and not line.startswith("-----")]
    return "".join(lines)


def public_key_fingerprint(body):
    """Snowflake style fingerprint: SHA256:<base64(sha256(DER SubjectPublicKeyInfo))>."""
    der = base64.b64decode(public_key_body(body))
    return "SHA256:" + base64.b64encode(hashlib.sha256(der).digest()).decode()


def _private_key_der(params):
    passphrase = params.get("private_key_passphrase")
    password = passphrase.encode() if passphrase else None
    if params.get("private_key"):
        data = params["private_key"].encode()
    else:
        with open(params["private_key_path"], "rb") as handle:
            data = handle.read()
    key = serialization.load_pem_private_key(data, password=password)
    return key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


# ---------------------------------------------------------------- connection

def check_dependencies(module):
    if not HAS_SNOWFLAKE:
        module.fail_json(msg=missing_required_lib("snowflake-connector-python"), exception=SNOWFLAKE_IMPORT_ERROR)
    if not HAS_CRYPTOGRAPHY:
        module.fail_json(msg=missing_required_lib("cryptography"), exception=CRYPTOGRAPHY_IMPORT_ERROR)


def connect(params):
    kwargs = dict(
        account=params["account"],
        user=params["user"],
        private_key=_private_key_der(params),
        application="snowflake_iac_ansible",
        session_parameters={"QUERY_TAG": QUERY_TAG},
    )
    if params.get("role"):
        kwargs["role"] = params["role"]
    if params.get("warehouse"):
        kwargs["warehouse"] = params["warehouse"]
    return snowflake.connector.connect(**kwargs)


def fetch_dicts(cur, sql, params=None):
    cur.execute(sql, params)
    if not cur.description:
        return []
    cols = [c[0].lower() for c in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def show_one(cur, kind, name, scope=None):
    """Return the SHOW row whose name matches exactly (LIKE treats _ as a wildcard)."""
    sql = "SHOW %s LIKE %s" % (kind, sql_string(name))
    if scope:
        sql += " IN " + scope
    for row in fetch_dicts(cur, sql):
        if str(row.get("name", "")).upper() == name.upper():
            return row
    return None


def to_jsonable(value):
    if isinstance(value, decimal.Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    return value


def run_plan(module, plan):
    """Connect, let plan(cur) return the statements needed, execute them unless in check mode.

    Every desired-state module follows this pattern, so `changed` is only true
    when Snowflake actually differs from the requested state.
    """
    check_dependencies(module)
    result = dict(changed=False, statements=[])
    conn = None
    try:
        conn = connect(module.params)
        cur = conn.cursor()
        statements = plan(cur)
        result["statements"] = statements
        result["changed"] = bool(statements)
        if statements and not module.check_mode:
            for statement in statements:
                cur.execute(statement)
    except ValueError as exc:
        module.fail_json(msg=str(exc), **result)
    except Exception as exc:  # connector errors carry useful text
        module.fail_json(msg="Snowflake error: %s" % exc, exception=traceback.format_exc(), **result)
    finally:
        if conn is not None:
            conn.close()
    module.exit_json(**result)
