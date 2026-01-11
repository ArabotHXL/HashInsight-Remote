import os
import threading
import webbrowser

import uvicorn

from .server import create_app
from .config import DEFAULT_LOCAL_PORT


def _open_browser(url: str) -> None:
    try:
        webbrowser.open(url)
    except Exception:
        pass


def run() -> None:
    port = int(os.environ.get("PICKAXE_PORT", DEFAULT_LOCAL_PORT))
    host = os.environ.get("PICKAXE_HOST", "127.0.0.1")

    app = create_app()
    url = f"http://{host}:{port}/"

    # Auto-open the local UI once the server is up
    threading.Timer(1.0, _open_browser, args=(url,)).start()

    uvicorn.run(app, host=host, port=port, log_level="info", use_colors=False)


if __name__ == "__main__":
    run()
