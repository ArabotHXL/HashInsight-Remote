# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

REPO_ROOT = Path(globals().get("SPECPATH", ".")).resolve()
ENTRY = REPO_ROOT / "collector_entry.py"
if not ENTRY.exists():
    raise SystemExit(f"Missing entry: {ENTRY}")

datas = []

def add_dir_as_datas(src_dir: Path, dest_root: str) -> None:
    """Recursively add directory contents as (src_file, dest_dir) tuples."""
    if not src_dir.exists():
        return
    for f in src_dir.rglob("*"):
        if f.is_file():
            rel_parent = f.relative_to(src_dir).parent
            dest = (Path(dest_root) / rel_parent).as_posix()
            datas.append((str(f), dest))

# Web UI assets (recursive)
add_dir_as_datas(REPO_ROOT / "pickaxe_app" / "web", "pickaxe_app/web")

# Docs (optional)
add_dir_as_datas(REPO_ROOT / "docs", "docs")

# Ship templates/examples at bundle root (optional but recommended)
for fname in ["collector_config.json", "bindings.csv", "README.md"]:
    p = REPO_ROOT / fname
    if p.exists():
        datas.append((str(p), "."))

hiddenimports = []
hiddenimports += collect_submodules("pickaxe_app")

# Web stack
for pkg in ["uvicorn", "fastapi", "starlette"]:
    try:
        hiddenimports += collect_submodules(pkg)
    except Exception:
        pass

# Common deps (safe tries)
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

# ONEDIR build (avoid onefile flash-exit / AV temp extraction issues)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PickaxeCollector",
    debug=False,
    strip=False,
    upx=False,
    console=False,  # Release: no console
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name="PickaxeCollector",
)
