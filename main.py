"""
main.py — VendorTrust FastAPI application entry point.
"""
import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import APP_ENV, PAYPAL_MODE
from app.web.routes import router

app = FastAPI(
    title="VendorTrust",
    description="AI-powered vendor payment safety — PayPal AI Hackathon 2026",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
)


@app.get("/healthz", tags=["Operations"])
@app.get("/health", tags=["Operations"])
async def health_check():
    """Operational health check endpoint for cloud load balancers and container orchestrators."""
    return {
        "status": "healthy",
        "service": "vendortrust",
        "mode": "PUBLIC_DEMO" if APP_ENV in ("production", "prod") else APP_ENV,
        "paypal_mode": PAYPAL_MODE,
        "version": "1.0.0",
    }


app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(router)

if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, workers=1)
