"""Lab settings: an app that reads its database and cache under its own
names, so Hangar's connector has to bridge them (docs/README.md)."""

import os
import secrets

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY") or secrets.token_hex(32)
DEBUG = False
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = []
MIDDLEWARE = []
ROOT_URLCONF = "conector.urls"
WSGI_APPLICATION = "conector.wsgi.application"
# The page talks to Postgres and Redis directly; the ORM is not used.
DATABASES = {}
USE_TZ = True
