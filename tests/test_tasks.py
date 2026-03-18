"""Tests for bbhunter.tasks (Celery task definitions)."""

from __future__ import annotations

import pytest


class TestCeleryTasks:
    def test_celery_app_exists(self):
        from bbhunter.tasks import app
        assert app.main == "bbhunter"

    def test_tasks_registered(self):
        from bbhunter.tasks import (
            run_recon, run_surface, run_scan,
            run_analysis, run_full_pipeline,
        )
        assert run_recon.name == "bbhunter.recon"
        assert run_surface.name == "bbhunter.surface"
        assert run_scan.name == "bbhunter.scan"
        assert run_analysis.name == "bbhunter.analysis"
        assert run_full_pipeline.name == "bbhunter.full_pipeline"

    def test_celery_config(self):
        from bbhunter.tasks import app
        assert app.conf.task_serializer == "json"
        assert app.conf.enable_utc is True
