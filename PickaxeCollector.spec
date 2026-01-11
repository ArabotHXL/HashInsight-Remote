# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules
from PyInstaller.building.datastruct import Tree

block_cipher = None

REPO_ROOT = Path(globals().get("SPECPATH", ".")).resolve()
ENTRY = REPO_ROOT / "collector_entry.py"
if not ENTRY.exists():
    raise SystemExit(f"Missing entry: {ENTRY}")

# --- Datas (static files) ---
datas = []

# Web UI assets (if present)
web_dir = REPO_ROOT / "pickaxe_app" / "web"
if web_dir.exists():
    datas.append(Tree(str(web_dir), prefix="pickaxe_app/web"))

# Ship example configs/templates with the portable bundle (optional but recommended)
for fname in ["collector_config.json", "bindings.csv", "README.md"]:
    p = REPO_ROOT / fname
    if p.exists():
        datas.append((str(p), "."))

# Docs (optional)
docs_dir = REPO_ROOT / "docs"
if docs_dir.exists():
    datas.append(Tree(str(docs_dir), prefix="docs"))

# --- Hidden imports (avoid runtime ModuleNotFoundError in frozen builds) ---
hiddenimports = []

# Your app
hiddenimports += collect_submodules("pickaxe_app")

# Web stack
hiddenimports += collect_submodules("uvicorn")
hiddenimports += collect_submodules("fastapi")
hiddenimports += collect_submodules("starlette")

# Common runtime deps used in FastAPI stacks and your collector modules
# (safe even if not all are installed; if a package isn't present, PyInstaller will ignore at build time)
for pkg in ["pydantic", "anyio", "httpx", "requests", "cryptography"]:
    try:
        hiddenimports += collect_submodules(pkg)
    except Exception:
        pass

a = Analysis(
    [str(ENTRY)],
    pathex=[str(REPO_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# IMPORTANT: ONEDIR build => EXE exclude_binaries=True + COLLECT at the end
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PickaxeCollector",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,           # <-- DO NOT use UPX (reduces AV false positives / “flash and exit”)
    console=False,       # <-- release: no console window
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name="PickaxeCollector",
)
