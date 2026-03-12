"""
Bootstrap script to start the Phishy backend API using Uvicorn.

Usage:
    python run.py

This will launch the FastAPI app defined in `main.py` on localhost:8000
with auto-reload enabled for development convenience.
"""

import uvicorn
import webbrowser
import threading
import time

if __name__ == "__main__":
    # open the browser shortly after the server starts
    def _open():
        # wait a moment for uvicorn to bind port
        time.sleep(1)
        webbrowser.open("http://localhost:8000/web.html")

    threading.Thread(target=_open, daemon=True).start()
    # `main:app` refers to the `app` instance inside backend/main.py
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
