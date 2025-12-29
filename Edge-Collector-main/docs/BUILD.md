# Build a standalone app (PyInstaller)

This project is Python-based. The simplest MVP path is to run it with a venv (`run_local.bat`).

If you want a single executable for on-site operators, use PyInstaller.

## Windows build (recommended)
1. Install Python 3.10+.
2. In PowerShell / CMD:
   ```bat
   python -m venv .venv
   call .venv\Scripts\activate
   pip install -r requirements.txt
   pip install pyinstaller
   ```
3. Build:
   ```bat
   pyinstaller --name HashInsightPickaxe --onefile --noconsole \
     --add-data "pickaxe_app\web;pickaxe_app\web" \
     -m pickaxe_app.main
   ```
4. The output binary will be in `dist\HashInsightPickaxe.exe`.

## macOS/Linux build
Same idea, but the output binary will be for your current OS:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install pyinstaller
pyinstaller --name HashInsightPickaxe --onefile \
  --add-data "pickaxe_app/web:pickaxe_app/web" \
  -m pickaxe_app.main
```

## Notes
- You cannot cross-compile Windows EXE from Linux reliably; build on the target OS.
- Config is stored under:
  - Windows: `C:\ProgramData\HashInsightPickaxe\config.json`
  - Others: `~/.hashinsight_pickaxe/config.json`
