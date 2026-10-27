from django.urls import path

from conector import views

urlpatterns = [
    path("healthz", views.healthz),
    path("", views.home),
]
