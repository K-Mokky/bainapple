# 바인애플 — Supabase / PostgreSQL edition

The `../secure-coding` second-hand marketplace ("바인애플"), repackaged to run
on **your Supabase project** instead of a local SQLite file.

- Supabase project: `https://fkfzxbvolgjbnjqzlerf.supabase.co`
- The application code under `market/` is a **verbatim copy** of the upstream
  `secure-coding` project. The upstream directory was **not modified**.
- The **only** changed file is `market/db.py`, swapped from SQLite to a
  PostgreSQL-backed data layer (psycopg 3). Every query stays fully
  parameterised, so the original SQL-injection defenses are preserved.

## What "moving it to Supabase" means here

Supabase is a managed **PostgreSQL** database (plus Auth/Storage/REST). A
server-rendered Flask + Socket.IO app like 바인애플 uses Supabase by connecting
to its Postgres database. So this build:

1. Creates the app's tables in your Supabase Postgres (`user`, `product`,
   `favorite`, `report`, `dm`, `notification`).
2. Copies the existing rows from the legacy `market.db` into them.
3. Runs the unchanged app against Supabase.

`market/db.py` transparently rewrites the app's SQLite SQL into valid
PostgreSQL at runtime:

| SQLite | PostgreSQL | why |
| --- | --- | --- |
| `?` | `%s` | psycopg placeholders |
| `FROM/JOIN/INTO/UPDATE user` | `... "user"` | `user` is a reserved word |
| `rowid` | `seq` | identity tie-breaker column on `dm`/`notification` |
| `IS ?` | `IS NOT DISTINCT FROM ?` | null-safe equality |
| `LIKE` | `ILIKE` | SQLite `LIKE` is case-insensitive |

## One thing you must provide: the DB connection string

The **publishable key** (`sb_publishable_…`) is a *browser/client* key — it only
reaches Supabase through PostgREST under Row-Level-Security and **cannot create
tables**. A server app needs the Postgres **connection string** (with the DB
password).

Get it from: **Supabase Dashboard → Project Settings → Database →
Connection string → URI**, then copy it into `.env`:

```env
# Session pooler (IPv4 — recommended):
DATABASE_URL=postgresql://postgres.fkfzxbvolgjbnjqzlerf:YOUR-DB-PASSWORD@aws-0-<REGION>.pooler.supabase.com:5432/postgres
```

`<REGION>` and the exact host come straight from the dashboard string; just
paste the whole URI and replace `[YOUR-PASSWORD]`.

## Activate (3 commands)

```bash
# 1) create the isolated env with all deps (Flask stack + psycopg + dotenv)
conda create --yes --name bainapple --clone secure_coding && conda activate bainapple
pip install "psycopg[binary]" python-dotenv

# 2) create the tables on Supabase AND copy the existing data
python migrate_from_sqlite.py            # idempotent; safe to re-run

# 3) run it
python app.py                            # http://127.0.0.1:5000
```

`python app.py` alone also creates the schema on first boot (via `init_db()`);
`migrate_from_sqlite.py` additionally loads the legacy rows.

> Prefer the dashboard? `schema_supabase.sql` is the exact DDL — paste it into
> **SQL Editor → Run**, then `python migrate_from_sqlite.py` for the data.

## Files

- `app.py` — entry point (loads `.env`, runs Socket.IO server).
- `market/` — the application (unchanged) + PostgreSQL `db.py`.
- `.env` / `.env.example` — configuration; put `DATABASE_URL` here.
- `migrate_from_sqlite.py` — create schema + copy `market.db.import` → Supabase.
- `schema_supabase.sql` — standalone DDL for the dashboard SQL editor.
- `market.db.import` — snapshot of the legacy SQLite data.
- `tests/`, `verify_local.py` — verification (see below).

## Verification performed

- Upstream test suite (47 tests) — **passes on SQLite and on PostgreSQL**.
- `verify_local.py` (25 checks) — register/login, product listing
  (`GROUP BY` + `ILIKE`), favorites + notifications (null-safe upsert),
  wallet, real-time DM over Socket.IO (window function + `seq`), duplicate-report
  `IntegrityError` handling, and admin joins — **all pass on PostgreSQL**.
- Live `python app.py` server — `/`, `/products`, `/login` return 200 with the
  security headers intact, backed by a real Postgres.

To reproduce against your own Postgres, set `DATABASE_URL` and run
`python -m pytest tests` or `python verify_local.py`.
