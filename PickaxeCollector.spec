# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules


def _collect_tree_as_datas(src_dir: Path, dest_prefix: str):
    """Return PyInstaller Analysis.datas entries as (src_file, dest_dir) 2-tuples.

    Why: Recent PyInstaller versions are stricter about 'datas' entry formats.
    Some helpers (e.g., Tree()) can yield 3-tuples internally, which can break
    builds in certain environments. This helper always returns 2-tuples.
    """
    out = []
    if not src_dir.exists():
        return out

    src_dir = src_dir.resolve()
    for p in src_dir.rglob("*"):
        if not p.is_file():
            continue
        rel_parent = p.relative_to(src_dir).parent
        # 'dest' is a directory inside the bundle
        dest_dir = (Path(dest_prefix) / rel_parent).as_posix()
        out.append((str(p), dest_dir))
    return out

block_cipher = None

# In PyInstaller spec files, __file__ can be unreliable depending on how the spec is executed.
# SPECPATH is injected by PyInstaller and points to the directory containing this spec.
ROOT = Path(globals().get("SPECPATH", ".")).resolve()

hiddenimports = []
# Uvicorn/FastAPI pull some modules dynamically; include submodules to avoid missing imports at runtime.
for pkg in ("uvicorn", "fastapi", "starlette"):
    hiddenimports += collect_submodules(pkg)

datas = []
web_dir = ROOT / "pickaxe_app" / "web"
if web_dir.exists():
    datas += _collect_tree_as_datas(web_dir, "pickaxe_app/web")

a = Analysis(
    ["collector_entry.py"],
    pathex=[str(ROOT)],
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
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
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
