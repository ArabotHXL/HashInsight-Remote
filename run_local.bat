@echo off
setlocal enabledelayedexpansion

REM HashInsight Remote - local runner (Windows)

if not exist .venv (
  echo Creating virtualenv...
  python -m venv .venv
)

call .venv\Scripts\activate

echo Installing/updating dependencies...
python -m pip install --upgrade pip >nul 2>&1
pip install -r requirements.txt

echo Starting HashInsight Remote UI on http://127.0.0.1:8711
python -m pickaxe_app.main

REM Keep window open so errors are visible
pause
