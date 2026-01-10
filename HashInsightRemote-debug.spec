# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for HashInsight Remote (debug build).

Same as HashInsightRemote.spec, but keeps a console window open for logs.
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

REPO_ROOT = Path(globals().get("SPECPATH", ".")).resolve()
ENTRY = REPO_ROOT / "collector_entry.py"
if not ENTRY.exists():
    raise SystemExit(f"Missing entrypoint: {ENTRY}")

# Ship web UI assets and default templates.
datas = [
    (str(REPO_ROOT / "pickaxe_app" / "web"), "pickaxe_app/web"),
]

for p in ["collector_config.json", "bindings.csv", "README.md"]:
    fp = REPO_ROOT / p
    if fp.exists():
        datas.append((str(fp), "."))

# Ship docs directory if present.
docs_dir = REPO_ROOT / "docs"
if docs_dir.exists():
    datas.append((str(docs_dir), "docs"))

hiddenimports = []
hiddenimports += collect_submodules("pickaxe_app")
hiddenimports += collect_submodules("uvicorn")
hiddenimports += collect_submodules("fastapi")
hiddenimports += collect_submodules("starlette")


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
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="HashInsightRemote-debug",
    console=True,
    upx=False,
)
