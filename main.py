"""
main.py — VendorTrust FastAPI application entry point.
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.web.routes import router

app = FastAPI(
    title="VendorTrust",
    description="AI-powered vendor payment safety — PayPal AI Hackathon 2026",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
)

app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(router)
