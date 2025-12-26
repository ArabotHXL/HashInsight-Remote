# --- PyInstaller compatibility: allow relative imports when executed as script ---
if __package__ in (None, ""):
    import os, sys
    pkg_root = os.path.dirname(os.path.dirname(__file__))  # repo root (parent of pickaxe_app)
    if pkg_root not in sys.path:
        sys.path.insert(0, pkg_root)
    __package__ = "pickaxe_app"
# -------------------------------------------------------------------------------
from .main import run

if __name__ == '__main__':
    run()
