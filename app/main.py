import os
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional

from app.core.nlp_engine import NLPEngine
from app.core.url_analyzer import URLAnalyzer
from app.core.header_analyzer import EmailHeaderAnalyzer
from app.core.risk_scorer import RiskScorer

app = FastAPI(
    title="PhishShield AI API",
    description="Multi-vector Social Engineering & Phishing Threat Engine",
    version="1.0.0"
)

# Setup templates
templates = Jinja2Templates(directory="app/templates")

# Instantiate NLP Engine
nlp_engine = NLPEngine(model_path="app/models/phishing_model.pkl")

class AnalysisRequest(BaseModel):
    text: Optional[str] = ""
    url: Optional[str] = ""
    headers: Optional[str] = ""

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    """Serve main cybersecurity web dashboard."""
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/api/health")
async def health_check():
    """Engine health status."""
    return {
        "status": "online",
        "nlp_model_loaded": nlp_engine.classifier is not None,
        "engine_version": "1.0.0"
    }

@app.post("/api/analyze")
async def analyze_threat(payload: AnalysisRequest):
    """
    Perform multi-vector analysis across text, embedded URLs, and headers.
    """
    # 1. NLP Text Analysis
    nlp_res = nlp_engine.predict(payload.text) if payload.text else {"score": 0.0, "flags": []}

    # 2. URL Analysis
    url_res = URLAnalyzer.analyze_url(payload.url) if payload.url else {"score": 0.0, "flags": []}

    # 3. Header Analysis
    header_res = EmailHeaderAnalyzer.analyze_headers(payload.headers) if payload.headers else {"score": 0.0, "flags": []}

    # 4. Composite Risk Aggregation
    result = RiskScorer.calculate_risk(
        nlp_res=nlp_res,
        url_res=url_res,
        header_res=header_res
    )

    return JSONResponse(content=result)
