from django.http import HttpResponseNotFound

from .models import StoreDomain

# Paths that do not belong to a store: Hangar's domain check and healthcheck.
OPEN_PATHS = {"/.well-known/hangar/domain-check", "/healthz"}


class ShopMiddleware:
    """Resolves the store from the Host header; unknown hosts get 404."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path in OPEN_PATHS:
            return self.get_response(request)
        host = request.get_host().split(":")[0].lower().rstrip(".")
        sd = StoreDomain.objects.select_related("store").filter(hostname=host, store__active=True).first()
        if sd is None:
            return HttpResponseNotFound("unknown store\n")
        request.store = sd.store
        return self.get_response(request)
