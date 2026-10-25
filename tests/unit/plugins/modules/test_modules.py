"""Unit tests for the pure planning functions of iacforge.snowflake_iac modules.

No Snowflake connection is needed: each module exposes build_statements(params, current).
"""
import base64
import hashlib

import pytest

from ansible_collections.iacforge.snowflake_iac.plugins.module_utils import snowflake_common as common
from ansible_collections.iacforge.snowflake_iac.plugins.modules import (
    snowflake_database, snowflake_grant, snowflake_resource_monitor, snowflake_role, snowflake_user,
    snowflake_warehouse,
)


# ------------------------------------------------------------------ common

@pytest.mark.parametrize("bad", ["", "1ABC", "WH; DROP DATABASE X", "wh-name", "a'b", None])
def test_ident_rejects_unsafe(bad):
    with pytest.raises(ValueError):
        common.ident(bad)


def test_ident_and_qualified():
    assert common.ident("wh_dev") == "WH_DEV"
    assert common.qualified("db.sch", 2) == "DB.SCH"
    with pytest.raises(ValueError):
        common.qualified("db", 2)


def test_sql_string_escapes_quotes():
    assert common.sql_string("it's") == "'it''s'"


def test_fingerprint_matches_sha256_of_der():
    der = b"\x30\x82fake-der"
    body = base64.b64encode(der).decode()
    pem = "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n" % body
    expected = "SHA256:" + base64.b64encode(hashlib.sha256(der).digest()).decode()
    assert common.public_key_fingerprint(body) == expected
    assert common.public_key_fingerprint(pem) == expected


# ------------------------------------------------------------------ warehouse

def wh(**kw):
    p = dict(name="WH_X", state="present", size=None, auto_suspend=None, auto_resume=None,
             resource_monitor=None, comment=None)
    p.update(kw)
    return p


def test_warehouse_create():
    stmts = snowflake_warehouse.build_statements(wh(size="xsmall", resource_monitor="rm_a"), None)
    assert stmts == ["CREATE WAREHOUSE WH_X WAREHOUSE_SIZE = XSMALL AUTO_SUSPEND = 60 AUTO_RESUME = TRUE "
                     "INITIALLY_SUSPENDED = TRUE RESOURCE_MONITOR = RM_A"]


def test_warehouse_idempotent():
    current = {"name": "WH_X", "size": "X-Small", "auto_suspend": 60, "auto_resume": "true",
               "resource_monitor": "RM_A", "comment": "", "state": "SUSPENDED"}
    assert snowflake_warehouse.build_statements(
        wh(size="XSMALL", auto_suspend=60, auto_resume=True, resource_monitor="RM_A"), current) == []


def test_warehouse_drift_and_suspend():
    current = {"size": "Small", "auto_suspend": 600, "auto_resume": "true", "resource_monitor": "null",
               "state": "STARTED"}
    stmts = snowflake_warehouse.build_statements(wh(state="suspended", size="XSMALL", auto_suspend=60), current)
    assert stmts == ["ALTER WAREHOUSE WH_X SET WAREHOUSE_SIZE = XSMALL AUTO_SUSPEND = 60",
                     "ALTER WAREHOUSE WH_X SUSPEND"]


def test_warehouse_absent():
    assert snowflake_warehouse.build_statements(wh(state="absent"), None) == []
    assert snowflake_warehouse.build_statements(wh(state="absent"), {"name": "WH_X"}) == ["DROP WAREHOUSE WH_X"]


def test_warehouse_rejects_bad_size():
    with pytest.raises(ValueError):
        snowflake_warehouse.build_statements(wh(size="HUGE"), None)


# ------------------------------------------------------------------ database / role

def test_database_creates_missing_schemas_only():
    p = dict(name="DB", state="present", schemas=["A", "B"], comment=None, data_retention_time_in_days=None)
    assert snowflake_database.build_statements(p, {"name": "DB"}, {"A"}) == ["CREATE SCHEMA DB.B"]


def test_role_grants_missing_parent():
    p = dict(name="R", state="present", comment=None, granted_to_roles=["SYSADMIN", "X"], revoke_others=False)
    assert snowflake_role.build_statements(p, {"name": "R"}, {"SYSADMIN"}) == ["GRANT ROLE R TO ROLE X"]


# ------------------------------------------------------------------ grant

def grant(**kw):
    p = dict(privileges=["USAGE"], object_type="warehouse", object_name="WH_X", to_role="READER", state="present")
    p.update(kw)
    return p


EMPTY = {"grants": set(), "objects": [], "future": set()}


def test_grant_direct():
    assert snowflake_grant.build_statements(grant(), EMPTY) == ["GRANT USAGE ON WAREHOUSE WH_X TO ROLE READER"]
    have = dict(EMPTY, grants={("USAGE", "WAREHOUSE", "WH_X")})
    assert snowflake_grant.build_statements(grant(), have) == []


def test_grant_rejects_all():
    with pytest.raises(ValueError):
        snowflake_grant.build_statements(grant(privileges=["ALL"]), EMPTY)


def test_grant_future_and_all_in_schema():
    p = grant(privileges=["SELECT"], object_type="future_views_in_schema", object_name="DB.S")
    assert snowflake_grant.build_statements(p, EMPTY) == ["GRANT SELECT ON FUTURE VIEWS IN SCHEMA DB.S TO ROLE READER"]
    assert snowflake_grant.build_statements(p, dict(EMPTY, future={("SELECT", "VIEW")})) == []

    p = grant(privileges=["SELECT"], object_type="all_views_in_schema", object_name="DB.S")
    partial = dict(EMPTY, objects=["V1", "V2"], grants={("SELECT", "VIEW", "DB.S.V1")})
    assert snowflake_grant.build_statements(p, partial) == ["GRANT SELECT ON ALL VIEWS IN SCHEMA DB.S TO ROLE READER"]


def test_grant_account_level():
    p = grant(privileges=["execute alert"], object_type="account", object_name=None)
    assert snowflake_grant.build_statements(p, EMPTY) == ["GRANT EXECUTE ALERT ON ACCOUNT TO ROLE READER"]
    assert snowflake_grant.build_statements(p, dict(EMPTY, grants={("EXECUTE ALERT", "ACCOUNT", "*")})) == []


# ------------------------------------------------------------------ user

def user(**kw):
    p = dict(name="SVC", state="present", type=None, login_name=None, display_name=None, email=None,
             comment=None, default_role=None, default_warehouse=None, disabled=None,
             rsa_public_key=None, rsa_public_key_2=None, roles=[], roles_scope=[])
    p.update(kw)
    return p


KEY = base64.b64encode(b"\x30\x82public-key-der").decode()


def test_user_key_unchanged_when_fingerprint_matches():
    current = {"row": {"name": "SVC"}, "fingerprints": {"RSA_PUBLIC_KEY": common.public_key_fingerprint(KEY)},
               "roles": {"R1"}}
    assert snowflake_user.build_statements(user(rsa_public_key=KEY, roles=["R1"]), current) == []


def test_user_rotation_and_movers():
    current = {"row": {"name": "SVC", "disabled": "false"}, "fingerprints": {"RSA_PUBLIC_KEY_2": "SHA256:old"},
               "roles": {"R_OLD", "OTHER"}}
    stmts = snowflake_user.build_statements(
        user(rsa_public_key_2="", roles=["R_NEW"], roles_scope=["R_OLD", "R_NEW"], disabled=True), current)
    assert stmts == ["ALTER USER SVC SET DISABLED = TRUE",
                     "ALTER USER SVC UNSET RSA_PUBLIC_KEY_2",
                     "GRANT ROLE R_NEW TO USER SVC",
                     "REVOKE ROLE R_OLD FROM USER SVC"]


def test_user_statement_masking():
    assert snowflake_user.mask("ALTER USER SVC SET RSA_PUBLIC_KEY = 'abc' ") == "ALTER USER SVC SET RSA_PUBLIC_KEY = '***' "


# ------------------------------------------------------------------ resource monitor

def rm(**kw):
    p = dict(name="RM", state="present", credit_quota=10, frequency="MONTHLY", notify_at=[75, 90],
             suspend_at=100, suspend_immediate_at=None, assign_to_account=False)
    p.update(kw)
    return p


def test_resource_monitor_idempotent():
    current = {"credit_quota": "10.00", "frequency": "MONTHLY", "notify_at": "75%,90%", "suspend_at": "100%",
               "suspend_immediately_at": None, "level": ""}
    assert snowflake_resource_monitor.build_statements(rm(), current) == []


def test_resource_monitor_quota_change():
    current = {"credit_quota": "10.00", "frequency": "MONTHLY", "notify_at": "75%,90%", "suspend_at": "100%"}
    assert snowflake_resource_monitor.build_statements(rm(credit_quota=20), current) == [
        "ALTER RESOURCE MONITOR RM SET CREDIT_QUOTA = 20"]
