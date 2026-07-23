"""Shared pytest fixtures.

The whole suite shares a single application instance (session scope). This
mirrors the real single-process deployment and, importantly, keeps exactly one
``create_app``/``SocketIO.init_app`` in the process — Flask-SocketIO binds its
JSON codec to the first initialised app, so multiple apps in one process break
socket event handling. Tests use unique usernames to stay independent.
"""
import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from market import create_app, socketio as _socketio  # noqa: E402
from market.config import Config  # noqa: E402


@pytest.fixture(scope="session")
def app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("market")

    class TestConfig(Config):
        TESTING = True
        SECRET_KEY = "test-secret-key-for-pytest-0123456789"
        SECRET_KEY_IS_EPHEMERAL = False
        DATABASE = str(tmp / "test.db")
        UPLOAD_FOLDER = str(tmp / "uploads")
        WTF_CSRF_ENABLED = False
        ADMIN_USERNAME = "admin"
        ADMIN_PASSWORD = "Admin12345"
        ADMIN_KEY_FILE = str(tmp / "admin_key.txt")
        REPORT_BLOCK_THRESHOLD = 3
        CHAT_MAX_MESSAGES = 3
        CHAT_WINDOW_SECONDS = 30

    application = create_app(TestConfig)
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def socketio():
    return _socketio


class Helper:
    def __init__(self, app):
        self.app = app

    def register(self, username, password="Password1"):
        c = self.app.test_client()
        c.post("/register", data={"username": username, "password": password, "confirm": password})
        return c

    def login(self, username, password="Password1"):
        c = self.app.test_client()
        c.post("/login", data={"username": username, "password": password})
        return c

    def user(self, username, password="Password1"):
        c = self.register(username, password)
        c.post("/login", data={"username": username, "password": password})
        return c

    def admin(self, password="Admin12345"):
        """Login as the seeded admin and pass the key-file gate."""
        c = self.login("admin", password)
        with open(self.app.config["ADMIN_KEY_FILE"], encoding="utf-8") as fh:
            key = fh.read().strip()
        c.post(
            "/admin/key",
            data={"key_file": (io.BytesIO(key.encode()), "admin_key.txt")},
            content_type="multipart/form-data",
        )
        return c


@pytest.fixture
def helper(app):
    return Helper(app)
