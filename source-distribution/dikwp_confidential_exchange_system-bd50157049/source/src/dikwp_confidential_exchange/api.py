"""Optional FastAPI wrapper.

Run: uvicorn dikwp_confidential_exchange.api:app --reload
This API is intentionally thin. Production deployments should put it behind SSO,
mTLS, rate limits, storage encryption, and an approval workflow.
"""
from __future__ import annotations

try:
    from fastapi import FastAPI, HTTPException
except Exception:  # pragma: no cover
    FastAPI = None

if FastAPI is not None:
    app = FastAPI(title="DIKWP Confidential Exchange", version="1.0.0")

    @app.get("/health")
    def health():
        return {"ok": True, "service": "DCE", "version": "1.0.0"}
else:  # pragma: no cover
    app = None
