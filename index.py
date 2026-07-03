"""Project root entrypoint for local development.

Allows `python3 index.py` to launch the Flask app that lives in `api/index.py`.
Uses a safer default than the nested module's debug reloader, which can fail in
restricted environments.
"""

import os

from api.index import app


if __name__ == "__main__":
    port = int(os.getenv("PORT", 3000))
    debug = os.getenv("FLASK_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
    app.run(host="0.0.0.0", port=port, debug=debug, use_reloader=False)
