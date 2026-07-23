"""Copy existing rows from the legacy SQLite database into Supabase/PostgreSQL.

Usage:
    python migrate_from_sqlite.py [path-to-sqlite.db]

Defaults to ``market.db.import`` (a copy of the upstream ``secure-coding``
``market.db``). Requires ``DATABASE_URL`` to point at the Supabase project.
Safe to re-run: every insert uses ``ON CONFLICT DO NOTHING``.
"""
from __future__ import annotations

import os
import sqlite3
import sys

try:
    from dotenv import load_dotenv

    load_dotenv()
except ModuleNotFoundError:
    pass

import psycopg

from market.db import _connect_postgres, _use_postgres

# (sqlite table, "does the receiving order matter for the seq tie-breaker?")
TABLE_ORDER = ["user", "product", "favorite", "report", "dm", "notification"]
ORDERED_BY_ROWID = {"dm", "notification"}


def _sqlite_columns(scur, table: str) -> list[str]:
    scur.execute(f'PRAGMA table_info("{table}")')
    return [row[1] for row in scur.fetchall()]


def migrate(sqlite_path: str) -> None:
    if not _use_postgres():
        sys.exit("DATABASE_URL is not a postgres:// URL; nothing to migrate into.")
    if not os.path.exists(sqlite_path):
        sys.exit(f"SQLite source not found: {sqlite_path}")

    src = sqlite3.connect(sqlite_path)
    scur = src.cursor()
    existing_tables = {
        r[0]
        for r in scur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }

    pg = _connect_postgres()
    total = 0
    with pg.cursor() as pcur:
        for table in TABLE_ORDER:
            if table not in existing_tables:
                continue
            cols = _sqlite_columns(scur, table)
            if not cols:
                continue
            order = " ORDER BY rowid" if table in ORDERED_BY_ROWID else ""
            col_list = ", ".join(f'"{c}"' for c in cols)
            rows = scur.execute(
                f'SELECT {col_list} FROM "{table}"{order}'
            ).fetchall()
            if not rows:
                print(f"  {table:<13} 0 rows")
                continue
            placeholders = ", ".join(["%s"] * len(cols))
            insert = (
                f'INSERT INTO "{table}" ({col_list}) VALUES ({placeholders}) '
                f"ON CONFLICT DO NOTHING"
            )
            inserted = 0
            for row in rows:
                pcur.execute(insert, row)
                inserted += pcur.rowcount or 0
            print(f"  {table:<13} {inserted}/{len(rows)} rows inserted")
            total += inserted
    pg.commit()
    pg.close()
    src.close()
    print(f"Done. {total} new row(s) migrated into Supabase.")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "market.db.import"
    if not _use_postgres():
        sys.exit("DATABASE_URL is not set to a postgres:// URL. Fill it in .env first.")
    # Building the app runs init_db(), which creates every table on Supabase
    # (idempotent) before we start copying rows into them.
    print("Ensuring schema on Supabase ...")
    from market import create_app

    create_app()
    print(f"Migrating from {path} -> Supabase PostgreSQL ...")
    migrate(path)
