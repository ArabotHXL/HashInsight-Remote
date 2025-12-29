# Entry point used by PyInstaller (Windows EXE build)
# Keep this file as *Python code* (do not paste requirements here).

import multiprocessing

from pickaxe_app.main import run


if __name__ == "__main__":
    multiprocessing.freeze_support()
    run()
