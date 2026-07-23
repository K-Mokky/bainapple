"""Data-access layer with a Supabase/PostgreSQL backend.

This is a drop-in replacement for the original SQLite ``market.db`` module.
The rest of the application is byte-for-byte identical to the upstream
``secure-coding`` project and still writes plain ``?``-parameterised SQL with a
bare ``user`` table name, ``rowid`` tie-breakers, SQLite ``IS`` null-equality
and case-insensitive ``LIKE``.

Rather than editing every call-site, this module wraps a real PostgreSQL
connection (psycopg 3) behind the exact same tiny API the app already uses
(``get_db``/``query_one``/``query_all``/``execute``) and transparently rewrites
each statement into valid PostgreSQL:

* ``?``                         -> ``%s``           (psycopg placeholders)
* ``FROM/JOIN/INTO/UPDATE user``-> ``... "user"``   (``user`` is a PG keyword)
* ``rowid``                     -> ``seq``          (identity tie-breaker column)
* ``IS ?``                      -> ``IS NOT DISTINCT FROM ?`` (null-safe compare)
* ``LIKE``                      -> ``ILIKE``        (SQLite LIKE is case-folding)

Every query stays fully parameterised, so the injection defenses of the
original code are preserved unchanged.

Backend selection is by environment:

* ``DATABASE_URL=postgresql://...``  -> PostgreSQL (Supabase) via psycopg
* otherwise                          -> local SQLite (unchanged dev fallback)
"""
from __future__ import annotations

import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone

from flask import current_app, g


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------
def _database_url() -> str | None:
    url = os.environ.get("DATABASE_URL")
    if url:
        return url.strip()
    return None


def _use_postgres() -> bool:
    url = _database_url()
    return bool(url and url.startswith(("postgres://", "postgresql://")))


# ---------------------------------------------------------------------------
# SQLite -> PostgreSQL statement rewriting
# ---------------------------------------------------------------------------
_RE_IS_PARAM = re.compile(r"\bIS\s+\?")
_RE_TABLE_USER = re.compile(r"\b(FROM|JOIN|INTO|UPDATE)\s+user\b", re.IGNORECASE)
_RE_ROWID = re.compile(r"\browid\b")
_RE_LIKE = re.compile(r"\bLIKE\b")


def translate(sql: str) -> str:
    """Rewrite an SQLite statement (with ``?`` params) into PostgreSQL."""
    # 1) null-safe equality must be handled while the placeholder is still "?".
    sql = _RE_IS_PARAM.sub("IS NOT DISTINCT FROM ?", sql)
    # 2) "user" is a reserved word in PostgreSQL -> quote the table references.
    sql = _RE_TABLE_USER.sub(lambda m: f'{m.group(1)} "user"', sql)
    # 3) there is no implicit rowid; use the identity "seq" tie-breaker column.
    sql = _RE_ROWID.sub("seq", sql)
    # 4) SQLite LIKE is case-insensitive for ASCII; ILIKE keeps that behaviour.
    sql = _RE_LIKE.sub("ILIKE", sql)
    # 5) finally swap the placeholder style.
    sql = sql.replace("?", "%s")
    return sql


class _PgConnection:
    """psycopg connection wrapped to mimic the sqlite3 API the app expects.

    Only the surface the application actually touches is implemented:
    ``execute`` (returning a cursor with ``fetchone``/``fetchall``/``rowcount``),
    ``commit``, ``rollback`` and ``close``.
    """

    def __init__(self, raw):
        self._raw = raw

    def execute(self, sql, params=()):
        import psycopg

        try:
            return self._raw.execute(translate(sql), tuple(params))
        except psycopg.errors.IntegrityError as exc:
            # moderation.py catches sqlite3.IntegrityError for duplicate reports.
            try:
                self._raw.rollback()
            except Exception:
                pass
            raise sqlite3.IntegrityError(str(exc)) from exc

    def commit(self):
        try:
            self._raw.commit()
        except Exception:
            pass

    def rollback(self):
        try:
            self._raw.rollback()
        except Exception:
            pass

    def close(self):
        self._raw.close()


def _with_sslmode(url: str) -> str:
    """Supabase requires TLS; ensure sslmode=require unless already specified."""
    if "sslmode=" in url:
        return url
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}sslmode=require"


def _connect_postgres():
    import psycopg
    from psycopg.rows import dict_row

    conn = psycopg.connect(
        _with_sslmode(_database_url()),
        autocommit=True,
        row_factory=dict_row,
    )
    # Disable client-side prepared statements so the connection is safe behind
    # Supabase's transaction pooler (port 6543) as well as the session pooler.
    conn.prepare_threshold = None
    return conn


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        if _use_postgres():
            db = g._database = _PgConnection(_connect_postgres())
        else:
            db = g._database = sqlite3.connect(current_app.config["DATABASE"])
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys = ON")
    return db


def close_db(exception=None):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()
        g._database = None


def query_one(sql: str, params: tuple = ()):
    return get_db().execute(sql, params).fetchone()


def query_all(sql: str, params: tuple = ()):
    return get_db().execute(sql, params).fetchall()


def execute(sql: str, params: tuple = (), commit: bool = True):
    db = get_db()
    cur = db.execute(sql, params)
    if commit:
        db.commit()
    return cur


# ---------------------------------------------------------------------------
# Schema (SQLite dev fallback keeps the original DDL verbatim)
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS user (
    id             TEXT PRIMARY KEY,
    username       TEXT UNIQUE NOT NULL,
    password_hash  TEXT NOT NULL,
    bio            TEXT NOT NULL DEFAULT '',
    bank_name      TEXT NOT NULL DEFAULT '',
    account_number TEXT NOT NULL DEFAULT '',
    account_holder TEXT NOT NULL DEFAULT '',
    is_admin       INTEGER NOT NULL DEFAULT 0,
    status         TEXT NOT NULL DEFAULT 'active',   -- active | dormant
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS product (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    description TEXT NOT NULL,
    price       INTEGER NOT NULL CHECK (price >= 0),
    seller_id   TEXT NOT NULL,
    image_path  TEXT,
    status      TEXT NOT NULL DEFAULT 'active',      -- active | blocked
    sale_status TEXT NOT NULL DEFAULT 'selling',     -- selling | sold
    category    TEXT NOT NULL DEFAULT '기타',
    created_at  TEXT NOT NULL,
    FOREIGN KEY (seller_id) REFERENCES user(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS favorite (
    user_id    TEXT NOT NULL,
    product_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, product_id),
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES product(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS report (
    id          TEXT PRIMARY KEY,
    reporter_id TEXT NOT NULL,
    target_type TEXT NOT NULL,                       -- user | product
    target_id   TEXT NOT NULL,
    reason      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE (reporter_id, target_type, target_id),
    FOREIGN KEY (reporter_id) REFERENCES user(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS dm (
    id          TEXT PRIMARY KEY,
    sender_id   TEXT NOT NULL,
    receiver_id TEXT NOT NULL,
    content     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    FOREIGN KEY (sender_id) REFERENCES user(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES user(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notification (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,                       -- receiver
    type       TEXT NOT NULL,                       -- favorite | dm
    actor_id   TEXT NOT NULL,                       -- who triggered it
    product_id TEXT,                                -- favorites only
    content    TEXT NOT NULL,
    is_read    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
    FOREIGN KEY (actor_id) REFERENCES user(id) ON DELETE CASCADE
);
"""

# Columns added after the initial release; applied to pre-existing databases.
_MIGRATIONS = [
    ("user", "bank_name", "TEXT NOT NULL DEFAULT ''"),
    ("user", "account_number", "TEXT NOT NULL DEFAULT ''"),
    ("user", "account_holder", "TEXT NOT NULL DEFAULT ''"),
    ("product", "sale_status", "TEXT NOT NULL DEFAULT 'selling'"),
    ("product", "category", "TEXT NOT NULL DEFAULT '기타'"),
]


def _ensure_columns(db):
    for table, column, decl in _MIGRATIONS:
        cols = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
        if column not in cols:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
    db.execute("DROP TABLE IF EXISTS message")


# ---------------------------------------------------------------------------
# PostgreSQL schema (dm/notification gain a monotonic ``seq`` identity used as
# the rowid tie-breaker; ``user`` is quoted because it is a reserved word).
# ---------------------------------------------------------------------------
PG_SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS "user" (
        id             text PRIMARY KEY,
        username       text UNIQUE NOT NULL,
        password_hash  text NOT NULL,
        bio            text NOT NULL DEFAULT '',
        bank_name      text NOT NULL DEFAULT '',
        account_number text NOT NULL DEFAULT '',
        account_holder text NOT NULL DEFAULT '',
        is_admin       integer NOT NULL DEFAULT 0,
        status         text NOT NULL DEFAULT 'active',
        created_at     text NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS product (
        id          text PRIMARY KEY,
        title       text NOT NULL,
        description text NOT NULL,
        price       integer NOT NULL CHECK (price >= 0),
        seller_id   text NOT NULL,
        image_path  text,
        status      text NOT NULL DEFAULT 'active',
        sale_status text NOT NULL DEFAULT 'selling',
        category    text NOT NULL DEFAULT '기타',
        created_at  text NOT NULL,
        FOREIGN KEY (seller_id) REFERENCES "user"(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS favorite (
        user_id    text NOT NULL,
        product_id text NOT NULL,
        created_at text NOT NULL,
        PRIMARY KEY (user_id, product_id),
        FOREIGN KEY (user_id) REFERENCES "user"(id) ON DELETE CASCADE,
        FOREIGN KEY (product_id) REFERENCES product(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS report (
        id          text PRIMARY KEY,
        reporter_id text NOT NULL,
        target_type text NOT NULL,
        target_id   text NOT NULL,
        reason      text NOT NULL,
        created_at  text NOT NULL,
        UNIQUE (reporter_id, target_type, target_id),
        FOREIGN KEY (reporter_id) REFERENCES "user"(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS dm (
        id          text PRIMARY KEY,
        sender_id   text NOT NULL,
        receiver_id text NOT NULL,
        content     text NOT NULL,
        created_at  text NOT NULL,
        seq         bigint GENERATED BY DEFAULT AS IDENTITY,
        FOREIGN KEY (sender_id) REFERENCES "user"(id) ON DELETE CASCADE,
        FOREIGN KEY (receiver_id) REFERENCES "user"(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS notification (
        id         text PRIMARY KEY,
        user_id    text NOT NULL,
        type       text NOT NULL,
        actor_id   text NOT NULL,
        product_id text,
        content    text NOT NULL,
        is_read    integer NOT NULL DEFAULT 0,
        created_at text NOT NULL,
        seq        bigint GENERATED BY DEFAULT AS IDENTITY,
        FOREIGN KEY (user_id) REFERENCES "user"(id) ON DELETE CASCADE,
        FOREIGN KEY (actor_id) REFERENCES "user"(id) ON DELETE CASCADE
    )
    """,
]

# Idempotent safety net for projects whose tables predate the wallet/category
# columns (mirrors the SQLite _MIGRATIONS list).
PG_MIGRATION_STATEMENTS = [
    'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS bank_name text NOT NULL DEFAULT \'\'',
    'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS account_number text NOT NULL DEFAULT \'\'',
    'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS account_holder text NOT NULL DEFAULT \'\'',
    "ALTER TABLE product ADD COLUMN IF NOT EXISTS sale_status text NOT NULL DEFAULT 'selling'",
    "ALTER TABLE product ADD COLUMN IF NOT EXISTS category text NOT NULL DEFAULT '기타'",
]


def init_db():
    """Create tables (idempotent) and seed an admin account if configured."""
    from werkzeug.security import generate_password_hash

    db = get_db()
    if _use_postgres():
        for stmt in PG_SCHEMA_STATEMENTS:
            db.execute(stmt)
        for stmt in PG_MIGRATION_STATEMENTS:
            db.execute(stmt)
        db.execute("DROP TABLE IF EXISTS message")
        db.commit()
    else:
        db.executescript(SCHEMA)
        _ensure_columns(db)
        db.commit()
    _seed_admin(generate_password_hash)


def _seed_admin(hasher):
    cfg = current_app.config
    username = cfg.get("ADMIN_USERNAME")
    password = cfg.get("ADMIN_PASSWORD")
    if not username or not password:
        return
    existing = query_one("SELECT id FROM user WHERE username = ?", (username,))
    if existing is not None:
        return
    execute(
        "INSERT INTO user (id, username, password_hash, bio, is_admin, status, created_at)"
        " VALUES (?, ?, ?, '', 1, 'active', ?)",
        (new_id(), username, hasher(password), _now()),
    )
