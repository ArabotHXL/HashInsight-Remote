@echo off
setlocal enabledelayedexpansion

REM HashInsight Pickaxe Collector - local runner (Windows)

if not exist .venv (
  echo Creating virtualenv...
  python -m venv .venv
)

call .venv\Scripts\activate

echo Installing/updating dependencies...
python -m pip install --upgrade pip >nul 2>&1
pip install -r requirements.txt

echo Starting Pickaxe UI on http://127.0.0.1:8711
python -m pickaxe_app.main

REM Keep window open so errors are visible
pause
