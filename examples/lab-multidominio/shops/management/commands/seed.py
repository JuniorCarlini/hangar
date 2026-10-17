import os

from django.core.management.base import BaseCommand

from django.conf import settings

from shops.models import DeployMark, Store, StoreDomain


class Command(BaseCommand):
    help = "Creates one store per hostname in LAB_DOMAINS (comma separated)."

    def handle(self, *args, **opts):
        DeployMark.objects.create(version=settings.LAB_VERSION)
        for host in filter(None, (h.strip().lower() for h in os.environ.get("LAB_DOMAINS", "").split(","))):
            if not StoreDomain.objects.filter(hostname=host).exists():
                StoreDomain.objects.create(store=Store.objects.create(name=host), hostname=host)
                self.stdout.write(f"store {host}")
