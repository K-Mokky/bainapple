"""Entry point (Supabase / PostgreSQL edition of the 바인애플 marketplace).

Run with:  python app.py

Environment (see .env / .env.example):
  DATABASE_URL   PostgreSQL connection string for the Supabase project.
                 When unset, the app falls back to a local SQLite file so it
                 still boots for offline development.
  SECRET_KEY     Flask session/CSRF secret (required for a real deployment).

The application package under ``market/`` is identical to the upstream
``secure-coding`` project; only ``market/db.py`` was swapped for a
PostgreSQL-backed data layer.
"""
import os

# Load .env *before* importing the app package: market/config.py reads the
# environment at import time.
try:
    from dotenv import load_dotenv

    load_dotenv()
except ModuleNotFoundError:
    pass

from market import create_app, socketio

app = create_app()

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "0").strip().lower() in {"1", "true", "yes", "on"}
    # debug defaults to OFF so tracebacks are never exposed in production.
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)
