#!/usr/bin/env bash
set -e

if [ ! -d ".venv" ]; then
  echo "Creating virtualenv..."
  python -m venv .venv
fi

source .venv/bin/activate

echo "Installing/updating dependencies..."
python -m pip install --upgrade pip >/dev/null 2>&1 || true
pip install -r requirements.txt

echo "Starting HashInsight Remote UI on http://127.0.0.1:8711"
python -m pickaxe_app.main
