# -*- coding: utf-8 -*-
# Copyright: (c) 2026, iacforge contributors
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Event-Driven Ansible source: poll PLATFORM_OPS.MONITORING.PLATFORM_EVENTS.

Snowflake alerts (role sf_monitoring) insert rows; each unprocessed row becomes an event
and is marked processed in the same session.

Arguments (all optional, fall back to SF_* environment variables):
  poll_seconds: 60
  events_table: PLATFORM_OPS.MONITORING.PLATFORM_EVENTS
  role, warehouse

Example rulebook source:
  - iacforge.snowflake_iac.snowflake_events:
      poll_seconds: 60
"""

import asyncio
import json
import os
import re

import snowflake.connector
from cryptography.hazmat.primitives import serialization

TABLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*\.[A-Za-z_][A-Za-z0-9_$]*\.[A-Za-z_][A-Za-z0-9_$]*$")


def _private_key():
    passphrase = os.getenv("SF_PRIVATE_KEY_PASSPHRASE")
    if os.getenv("SF_PRIVATE_KEY"):
        data = os.environ["SF_PRIVATE_KEY"].encode()
    else:
        with open(os.path.expanduser(os.environ["SF_PRIVATE_KEY_PATH"]), "rb") as handle:
            data = handle.read()
    key = serialization.load_pem_private_key(data, password=passphrase.encode() if passphrase else None)
    return key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _poll(args):
    table = args.get("events_table", "PLATFORM_OPS.MONITORING.PLATFORM_EVENTS")
    if not TABLE_RE.match(table):
        raise ValueError("events_table must be DB.SCHEMA.TABLE")
    warehouse = args.get("warehouse") or os.getenv("SF_WAREHOUSE")
    if not warehouse:
        raise ValueError("snowflake_events needs a warehouse: set the 'warehouse' source argument or SF_WAREHOUSE")
    conn = snowflake.connector.connect(
        account=os.environ["SF_ACCOUNT"], user=os.environ["SF_USER"], private_key=_private_key(),
        role=args.get("role") or os.getenv("SF_ROLE"), warehouse=warehouse,
        session_parameters={"QUERY_TAG": "eda:iacforge.snowflake_iac.snowflake_events"},
    )
    try:
        cur = conn.cursor()
        cur.execute("SELECT event_id, event_type, object_name, detail, created_at FROM %s "
                    "WHERE processed_at IS NULL ORDER BY event_id LIMIT 100" % table)
        rows = cur.fetchall()
        if rows:
            ids = [r[0] for r in rows]
            cur.execute("UPDATE %s SET processed_at = CURRENT_TIMESTAMP() WHERE event_id IN (%s)"
                        % (table, ",".join(["%s"] * len(ids))), ids)
        return rows
    finally:
        conn.close()


async def main(queue, args):
    interval = int(args.get("poll_seconds", 60))
    while True:
        for event_id, event_type, object_name, detail, created_at in await asyncio.to_thread(_poll, args):
            await queue.put({
                "event_id": event_id,
                "event_type": event_type,
                "object_name": object_name,
                "detail": json.loads(detail) if isinstance(detail, str) else (detail or {}),
                "created_at": str(created_at),
            })
        await asyncio.sleep(interval)


if __name__ == "__main__":
    class _PrintQueue:
        async def put(self, event):
            print(event)

    asyncio.run(main(_PrintQueue(), {"poll_seconds": 10}))
