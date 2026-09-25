@echo off
title PhishShield AI Backend & Dashboard
echo ========================================================
echo   Starting PhishShield AI (RoBERTa Transformer Engine)
echo   Dashboard URL: http://127.0.0.1:8000
echo ========================================================
cd /d %~dp0
call venv\Scripts\activate.bat
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
pause
