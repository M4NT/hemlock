"""Hemlock REST API server (v4.0).

FastAPI-based. FastAPI is an optional dependency — install with:
    pip install 'hemlock-rag[api]'

Endpoints:
    GET  /health
    GET  /plugins
    GET  /plugins/{name}
    POST /eval
    POST /threat-model
    POST /report
    GET  /watch/history

Usage:
    from hemlock.api_server import create_app
    app = create_app()
    # uvicorn hemlock.api_server:create_app --factory
"""

# NOTE: intentionally no `from __future__ import annotations` — FastAPI resolves
# endpoint parameter annotations at decoration time, and stringized annotations
# from PEP 563 break body-model detection for locally referenced classes.

import json
import os
from typing import Any, Optional

_INSTALL_HINT = (
    "FastAPI is required for the Hemlock API server.\n"
    "Install with: pip install 'hemlock-rag[api]'"
)


def create_app() -> Any:
    try:
        from fastapi import Body, FastAPI, HTTPException
        from pydantic import BaseModel
    except ImportError as exc:  # pragma: no cover - exercised only without fastapi
        raise ImportError(_INSTALL_HINT) from exc

    from hemlock.plugin_registry import REGISTRY

    app = FastAPI(title="Hemlock API", version=_version())
    REGISTRY.discover()

    class EvalRequest(BaseModel):
        attack_names: Optional[list[str]] = None
        categories: Optional[list[str]] = None
        model_name: str = "mock"
        variants_per_attack: Optional[int] = None

    class ThreatModelRequest(BaseModel):
        target: str = "hemlock-lab"
        channels: Optional[list[str]] = None

    class ReportRequest(BaseModel):
        template: str = "technical"
        channels: Optional[list[str]] = None
        target: str = "hemlock-lab"

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "version": _version()}

    @app.get("/plugins")
    def plugins() -> dict:
        return REGISTRY.to_dict()

    @app.get("/plugins/{name}")
    def plugin(name: str) -> dict:
        info = REGISTRY.get(name)
        if info is None:
            raise HTTPException(status_code=404, detail=f"plugin not found: {name}")
        return {
            "name": info.name,
            "type": info.type,
            "source": info.source,
            "version": info.version,
            "class": info.cls.__name__,
        }

    @app.post("/eval")
    def eval_endpoint(req: EvalRequest = Body(default=EvalRequest())) -> dict:
        from hemlock.eval_benchmark import EvalBenchmark

        bench = EvalBenchmark.from_mock(
            attack_names=req.attack_names,
            categories=req.categories,
            model_name=req.model_name,
            variants_per_attack=req.variants_per_attack,
        )
        return bench.run().to_dict()

    @app.post("/threat-model")
    def threat_model_endpoint(
        req: ThreatModelRequest = Body(default=ThreatModelRequest()),
    ) -> dict:
        from hemlock.hem_session import HemSession

        session = HemSession.mock(target=req.target, channels=req.channels)
        return session.run().to_dict()

    @app.post("/report")
    def report_endpoint(req: ReportRequest = Body(default=ReportRequest())) -> dict:
        if req.template not in ("executive", "technical"):
            raise HTTPException(status_code=400, detail="template must be executive|technical")
        from hemlock.hem_session import HemSession
        from hemlock.report_templates import render

        session = HemSession.mock(target=req.target, channels=req.channels)
        report = session.run()
        return {"markdown": render(report, template=req.template)}

    @app.get("/watch/history")
    def watch_history() -> dict:
        path = "watch_history.json"
        if not os.path.exists(path):
            return {"history": []}
        try:
            with open(path, encoding="utf-8") as f:
                return {"history": json.load(f)}
        except (json.JSONDecodeError, OSError):
            return {"history": []}

    @app.get("/history")
    def history_alias() -> dict:
        """Alias for /watch/history — returns the assessment history list."""
        path = "watch_history.json"
        if not os.path.exists(path):
            return {"history": []}
        try:
            with open(path, encoding="utf-8") as f:
                return {"history": json.load(f)}
        except (json.JSONDecodeError, OSError):
            return {"history": []}

    from hemlock.dashboard import get_dashboard_router
    app.include_router(get_dashboard_router())

    return app


def _version() -> str:
    try:
        from hemlock import __version__
        return __version__
    except Exception:
        return "0.0.0"
