# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

REPO_ROOT = Path(globals().get("SPECPATH", ".")).resolve()

hiddenimports = []
hiddenimports += collect_submodules("pickaxe_app")
# Safety: vendor collector modules are dynamically imported in a few places.
hiddenimports += collect_submodules("pickaxe_app.vendor_edge_collector")

datas = []
# Include static UI assets (pickaxe_app/static/*) and any other non-.py package files.
datas += collect_data_files("pickaxe_app", include_py_files=False)

a = Analysis(
    ["collector_entry.py"],
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
    [],
    exclude_binaries=True,
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
    upx_exclude=[],
    name="PickaxeCollector",
)