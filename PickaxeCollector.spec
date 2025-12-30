# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

# NOTE:
# GitHub Actions / PyInstaller may execute this spec in a context where __file__ is not defined.
# Use SPECPATH (provided by PyInstaller) as the anchor for relative paths.
ROOT = Path(SPECPATH).resolve().parent

# --- Web UI assets (pickaxe_app/web) ---
# PyInstaller expects "datas" entries as 2-tuples: (SRC, DEST_DIR) where DEST_DIR is RELATIVE.
# Avoid Tree() here to keep compatibility across PyInstaller versions.
datas = []
web_dir = ROOT / "pickaxe_app" / "web"
if web_dir.exists():
    for p in web_dir.rglob("*"):
        if p.is_file():
            rel = p.relative_to(web_dir)
            dest_dir = str(Path("pickaxe_app") / "web" / rel.parent)
            datas.append((str(p), dest_dir))

# --- Hidden imports (FastAPI/Uvicorn) ---
hiddenimports = []
hiddenimports += collect_submodules("uvicorn")
hiddenimports += collect_submodules("fastapi")
hiddenimports += collect_submodules("starlette")
hiddenimports += collect_submodules("pydantic")
hiddenimports += collect_submodules("pydantic_core")

a = Analysis(
    ["collector_entry.py"],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="PickaxeCollector",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    name="PickaxeCollector",
)
