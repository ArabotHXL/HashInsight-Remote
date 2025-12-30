# -*- mode: python ; coding: utf-8 -*-

"""PyInstaller spec for PickaxeCollector.

Key points:
- Explicitly bundle the embedded web UI under pickaxe_app/web (index.html + static/*).
- Keep datas items as 2-tuples (src, dest_dir). PyInstaller 6.17 expects this.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules


block_cipher = None


REPO_ROOT = Path(__file__).resolve().parent
ENTRY = REPO_ROOT / "collector_entry.py"


def _datas_tree(src_dir: Path, dest_prefix: str) -> list[tuple[str, str]]:
    """Return PyInstaller datas entries for every file under src_dir.

    Each entry is (absolute_src_file, relative_dest_dir).
    """
    items: list[tuple[str, str]] = []
    if not src_dir.exists():
        return items

    for p in src_dir.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(src_dir)
        dest_dir = (Path(dest_prefix) / rel.parent).as_posix()
        items.append((str(p), dest_dir))
    return items


datas: list[tuple[str, str]] = []

# Bundle embedded UI assets (avoid 500 on GET / when frozen).
datas += _datas_tree(REPO_ROOT / "pickaxe_app" / "web", "pickaxe_app/web")


hiddenimports: list[str] = []
for pkg in ("pickaxe_app", "fastapi", "starlette", "uvicorn", "anyio"):
    hiddenimports += collect_submodules(pkg)


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
    name="PickaxeCollector",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
