"""Lab settings: a tiny multi-store app to test Hangar's dynamic domains."""

import os
import secrets

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY") or secrets.token_hex(32)
DEBUG = False
# Every Host reaches the app; ShopMiddleware answers 404 for unknown ones.
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = ["django.contrib.contenttypes", "shops"]
MIDDLEWARE = ["shops.middleware.ShopMiddleware"]
ROOT_URLCONF = "lab.urls"
WSGI_APPLICATION = "lab.wsgi.application"
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("LAB_DB", "/tmp/lab.db"),
    }
}
# In Hangar: DATABASE_URL=${{db.DATABASE_URL}} (the Postgres template export).
if os.environ.get("DATABASE_URL"):
    from urllib.parse import unquote, urlparse

    u = urlparse(os.environ["DATABASE_URL"])
    DATABASES["default"] = {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": u.path.lstrip("/"),
        "USER": unquote(u.username or ""),
        "PASSWORD": unquote(u.password or ""),
        "HOST": u.hostname,
        "PORT": u.port or 5432,
        "CONN_MAX_AGE": 60,
    }

# Shown on every page, to see which version answered during a deploy.
LAB_VERSION = os.environ.get("LAB_VERSION", "1")
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True
# Caddy terminates TLS and sets X-Forwarded-Proto.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Shared with Hangar, delivered on deploy (docs/03).
DOMAIN_CHECK_SECRET = os.environ.get("HANGAR_DOMAIN_CHECK_SECRET", "")
