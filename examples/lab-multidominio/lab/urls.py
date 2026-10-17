from django.urls import path

from shops import views

urlpatterns = [
    path(".well-known/hangar/domain-check", views.domain_check),
    path("healthz", views.healthz),
    path("", views.home),
]
