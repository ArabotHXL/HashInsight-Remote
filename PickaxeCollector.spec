# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# SPECPATH is set by PyInstaller when running from a .spec file.
REPO_ROOT = Path(globals().get("SPECPATH", ".")).resolve()

ENTRY = REPO_ROOT / "collector_entry.py"
if not ENTRY.exists():
    raise SystemExit(f"Missing entry file: {ENTRY}")

# Static assets served by FastAPI (if enabled)
datas = [
    (str(REPO_ROOT / "pickaxe_app" / "web"), "pickaxe_app/web"),
]

# FastAPI/Starlette ship a small amount of non-py data (e.g., templates)
datas += collect_data_files("fastapi")
datas += collect_data_files("starlette")

# Hidden imports: uvicorn + fastapi load some modules dynamically.
hiddenimports = []
for pkg in [
    "pickaxe_app",
    "uvicorn",
    "fastapi",
    "starlette",
    "pydantic",
    "pydantic_settings",
    "anyio",
    "sniffio",
]:
    hiddenimports += collect_submodules(pkg)

hiddenimports = sorted(set(hiddenimports))

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
    name="PickaxeCollector",
    console=True,
    upx=True,
)
