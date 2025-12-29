# -*- mode: python ; coding: utf-8 -*-

import os
from pathlib import Path

from PyInstaller.building.datastruct import Tree
from PyInstaller.utils.hooks import collect_all, collect_submodules

# NOTE:
# PyInstaller executes .spec files via exec() and does NOT always set __file__.
# SPECPATH is provided by PyInstaller and reliably points to the spec directory.
REPO_ROOT = Path(globals().get('SPECPATH', os.getcwd())).resolve()

# --- Data files (UI / web assets) ---
# The FastAPI app serves files from pickaxe_app/web/*.
# Tree() ensures the entire folder is bundled (recursively) and extracted at runtime.
web_dir = REPO_ROOT / 'pickaxe_app' / 'web'
_datas = []
if web_dir.exists():
    _datas.append(Tree(str(web_dir), prefix='pickaxe_app/web'))

# --- Hidden imports / package collection ---
_hidden = []
_binaries = []

# Always include our application package and the vendored collector.
_hidden += collect_submodules('pickaxe_app')
_hidden += collect_submodules('pickaxe_app.vendor_edge_collector')

# Force-include key runtime dependencies to avoid "works in dev, crashes in EXE".
# collect_all pulls datas, binaries and hidden imports for the package.
for pkg in [
    'fastapi',
    'starlette',
    'pydantic',
    'pydantic_core',
    'uvicorn',
    'anyio',
    'httpx',
    'requests',
]:
    try:
        d, b, h = collect_all(pkg)
        _datas += d
        _binaries += b
        _hidden += h
    except Exception:
        # If a package isn't installed in the build environment, fail-fast in CI.
        # (The GitHub Actions workflow validates imports before running PyInstaller.)
        pass

block_cipher = None

a = Analysis(
    ['collector_entry.py'],
    pathex=[str(REPO_ROOT)],
    binaries=_binaries,
    datas=_datas,
    hiddenimports=_hidden,
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
    a.zipfiles,
    a.datas,
    [],
    name='PickaxeCollector',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
