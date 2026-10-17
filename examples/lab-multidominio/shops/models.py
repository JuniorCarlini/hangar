from django.db import models


class Store(models.Model):
    name = models.CharField(max_length=100)
    active = models.BooleanField(default=True)


class StoreDomain(models.Model):
    store = models.ForeignKey(Store, on_delete=models.CASCADE, related_name="domains")
    hostname = models.CharField(max_length=253, unique=True)


class DeployMark(models.Model):
    """One row per run of the seed command: tells how many times the
    pre-deploy ran (it must be once per deploy)."""

    created_at = models.DateTimeField(auto_now_add=True)
    version = models.CharField(max_length=20)
