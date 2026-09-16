@echo off
echo Starting ThreatTrace-AI Intelligence API on http://localhost:8000 ...
"C:\Users\hp\AppData\Local\Programs\Python\Python311\python.exe" -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
pause
