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

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

# Setup templates
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Instantiate NLP Engine
nlp_engine = NLPEngine()

class AnalysisRequest(BaseModel):
    text: Optional[str] = ""
    url: Optional[str] = ""
    headers: Optional[str] = ""

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    """Serve main cybersecurity web dashboard."""
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/test-lab", response_class=HTMLResponse)
async def serve_test_lab(request: Request):
    """Serve interactive phishing & malicious link simulation test lab."""
    return templates.TemplateResponse(request=request, name="test_lab.html")

@app.get("/api/health")
async def health_check():
    """Engine health status and AI model details."""
    ai_status = nlp_engine.get_status()
    return {
        "status": "online",
        "nlp_model_loaded": nlp_engine.classifier is not None or ai_status.get("roberta_ready"),
        "ai_engine": ai_status,
        "engine_version": "1.1.0"
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
