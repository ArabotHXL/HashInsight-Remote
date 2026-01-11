# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules
from PyInstaller.building.datastruct import Tree

block_cipher = None

REPO_ROOT = Path(globals().get("SPECPATH", ".")).resolve()
ENTRY = REPO_ROOT / "collector_entry.py"
if not ENTRY.exists():
    raise SystemExit(f"Missing entry: {ENTRY}")

datas = []

web_dir = REPO_ROOT / "pickaxe_app" / "web"
if web_dir.exists():
    datas.append(Tree(str(web_dir), prefix="pickaxe_app/web"))

for fname in ["collector_config.json", "bindings.csv", "README.md"]:
    p = REPO_ROOT / fname
    if p.exists():
        datas.append((str(p), "."))

docs_dir = REPO_ROOT / "docs"
if docs_dir.exists():
    datas.append(Tree(str(docs_dir), prefix="docs"))

hiddenimports = []
hiddenimports += collect_submodules("pickaxe_app")
hiddenimports += collect_submodules("uvicorn")
hiddenimports += collect_submodules("fastapi")
hiddenimports += collect_submodules("starlette")

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

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PickaxeCollector-debug",
    debug=True,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,        # <-- debug: keep console so you can see crashes
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name="PickaxeCollector-debug",
)
