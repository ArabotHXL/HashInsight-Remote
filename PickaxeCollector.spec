# -*- mode: python ; coding: utf-8 -*-

"""PyInstaller spec for PickaxeCollector.

Compatibility goals
- Works in GitHub Actions and local builds.
- Does not rely on __file__ being defined (spec can be exec()'d).
- Ensures `datas` entries are 2-tuples (src, dest) to avoid:
    ValueError: too many values to unpack (expected 2)
  across PyInstaller versions.
"""

import os
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files

try:
    from PyInstaller.building.datastruct import Tree
except Exception:
    Tree = None

# In CI, PyInstaller executes the spec via exec(), where __file__ may be unset.
# Using CWD is deterministic for both local and GitHub Actions builds.
ROOT = Path(os.getcwd()).resolve()
WEB_DIR = ROOT / 'pickaxe_app' / 'web'


def _normalize_datas(iterable):
    """Return a list of 2-tuples (src, dest).

    Some PyInstaller helpers can yield tuples with >2 elements depending on version.
    PyInstaller's internal format_binaries_and_datas expects exactly (src, dest).
    """
    out = []
    if iterable is None:
        return out

    try:
        iterator = iter(iterable)
    except TypeError:
        iterator = iter([iterable])

    for entry in iterator:
        if entry is None:
            continue

        # Entry is already a tuple/list
        if isinstance(entry, (tuple, list)):
            if len(entry) >= 2:
                out.append((entry[0], entry[1]))
            continue

        # Entry itself is iterable (e.g., a Tree object yielding tuples)
        try:
            for sub in entry:
                if isinstance(sub, (tuple, list)) and len(sub) >= 2:
                    out.append((sub[0], sub[1]))
        except TypeError:
            # Non-iterable entry; ignore
            pass

    return out


datas = []

# Bundle embedded web UI assets (if present)
if Tree is not None and WEB_DIR.exists():
    datas.extend(_normalize_datas(Tree(str(WEB_DIR), prefix='pickaxe_app/web')))

# Bundle package resources (and .py files for reliability in one-file mode)
datas.extend(_normalize_datas(collect_data_files('pickaxe_app', include_py_files=True)))

# Uvicorn/FastAPI sometimes use dynamic imports; being explicit avoids runtime misses.
hiddenimports = [
    'uvicorn',
    'uvicorn.logging',
    'uvicorn.loops',
    'uvicorn.protocols',
    'uvicorn.protocols.http',
    'uvicorn.protocols.websockets',
    'uvicorn.lifespan',
    'uvicorn.lifespan.on',
    'fastapi',
    'starlette',
]


a = Analysis(
    ['collector_entry.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure)

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
    upx=sys.platform.startswith('win'),
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
)
