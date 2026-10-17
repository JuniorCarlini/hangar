import hashlib
import os
import hmac
import time

from django.conf import settings
from django.http import HttpResponse, HttpResponseForbidden, HttpResponseNotFound

from .models import StoreDomain

MAX_SKEW = 60  # seconds


def home(request):
    return HttpResponse(f"store: {request.store.name} (v{settings.LAB_VERSION}, build {os.environ.get('LAB_BUILD', '?')})\n", content_type="text/plain")


def healthz(request):
    """Ready when the database answers (Hangar's healthcheck path)."""
    StoreDomain.objects.exists()
    return HttpResponse("ok\n", content_type="text/plain")


def domain_check(request):
    """Hangar asks whether a hostname belongs to an active store.

    The request is signed: hex(HMAC-SHA256(secret, "<hostname>|<timestamp>")).
    200 = issue the certificate; 404 = unknown; 403 = bad signature.
    """
    secret = settings.DOMAIN_CHECK_SECRET.encode()
    host = request.GET.get("domain", "")
    ts = request.headers.get("X-Hangar-Timestamp", "")
    sig = request.headers.get("X-Hangar-Signature", "")
    if not secret or not ts.isdigit() or abs(time.time() - int(ts)) > MAX_SKEW:
        return HttpResponseForbidden()
    want = hmac.new(secret, f"{host}|{ts}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, sig):
        return HttpResponseForbidden()
    if StoreDomain.objects.filter(hostname=host, store__active=True).exists():
        return HttpResponse(status=200)
    return HttpResponseNotFound()
