from __future__ import annotations
import os

try:
    from celery import Celery

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "lazarus_backend.settings")
    app = Celery("lazarus_backend")
    app.config_from_object("django.conf:settings", namespace="CELERY")
    app.autodiscover_tasks()
except ImportError:  # pragma: no cover - graceful fallback when Celery is not installed
    app = None
