# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

from PyInstaller.building.datastruct import Tree
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

# When PyInstaller executes a spec file, __file__ is not always defined.
# SPECPATH is the reliable way to locate the spec directory.
REPO_ROOT = Path(globals().get('SPECPATH', '.')).resolve()

ENTRY = REPO_ROOT / 'collector_entry.py'
if not ENTRY.exists():
    # Fallback: some repos use pickaxe_app/__main__.py
    alt = REPO_ROOT / 'pickaxe_app' / '__main__.py'
    if alt.exists():
        ENTRY = alt
    else:
        raise SystemExit(
            f"Could not find entry script. Tried: {REPO_ROOT / 'collector_entry.py'} and {alt}"
        )

# ---------- Data files (web UI assets) ----------
# IMPORTANT:
# PyInstaller expects (SRC, DEST_DIR) where DEST_DIR is a *relative directory* inside the bundle.
# Do NOT use absolute paths for DEST_DIR.

datas = []
web_dir = REPO_ROOT / 'pickaxe_app' / 'web'
if web_dir.exists():
    # Tree() will include the directory recursively.
    # prefix must be relative; otherwise PyInstaller will error: "DEST_DIR must be a relative path".
    datas.append(Tree(str(web_dir), prefix='pickaxe_app/web'))

# ---------- Hidden imports (FastAPI / Uvicorn) ----------
# Uvicorn in particular relies on dynamic imports.
hiddenimports = (
    collect_submodules('fastapi')
    + collect_submodules('starlette')
    + collect_submodules('uvicorn')
    + collect_submodules('uvicorn.loops')
    + collect_submodules('uvicorn.protocols')
    + collect_submodules('uvicorn.lifespan')
)

a = Analysis(
    [str(ENTRY)],
    pathex=[str(REPO_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
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
    a.datas,
    [],
    name='PickaxeCollector',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
