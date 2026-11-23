"""ShopLab testbed application factory and launcher.

Switch between versions with --mode (or the SHOPLAB_MODE environment variable):

    python -m testbed.app --mode vulnerable --port 5001
    python -m testbed.app --mode patched    --port 5002

Both versions can run at the same time on different ports; each uses its own
SQLite database file (testbed/instance/shoplab_<mode>.db).
"""

import argparse
import os
import sys

from flask import Flask, session

from . import models
from .common_routes import register_common_routes
from .database import db_path_for_mode, init_db
from .security import csrf_field, csrf_protect

MODES = ("vulnerable", "patched")


def create_app(mode="vulnerable", database=None, init_database=True):
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")

    app = Flask(__name__)
    app.config.update(
        MODE=mode,
        DATABASE=database or db_path_for_mode(mode),
        SECRET_KEY=os.environ.get("SHOPLAB_SECRET_KEY", f"shoplab-{mode}-dev-secret-key-change-me"),
    )

    if mode == "vulnerable":
        from .vulnerable_routes import CSRF_EXEMPT_ENDPOINTS, register_vulnerable_routes

        # VULN-10: insecure session cookie - readable from JavaScript and
        # sent on cross-site requests (no HttpOnly, no SameSite attribute).
        app.config.update(SESSION_COOKIE_HTTPONLY=False, SESSION_COOKIE_SAMESITE=None)
        app.config["CSRF_EXEMPT_ENDPOINTS"] = CSRF_EXEMPT_ENDPOINTS
        register_vulnerable_routes(app)
    else:
        from .patched_routes import CSRF_EXEMPT_ENDPOINTS, register_patched_routes

        # Secure cookie attributes. SESSION_COOKIE_SECURE is left False only
        # because the local testbed is served over plain HTTP; enable it for HTTPS.
        app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
        app.config["CSRF_EXEMPT_ENDPOINTS"] = CSRF_EXEMPT_ENDPOINTS
        register_patched_routes(app)

    register_common_routes(app)
    app.before_request(csrf_protect)
    app.teardown_appcontext(models.close_db)

    @app.context_processor
    def inject_globals():
        return {
            "csrf_field": csrf_field,
            "mode": mode,
            "current_user": {"id": session.get("user_id"), "username": session.get("username")},
        }

    if init_database and not os.path.exists(app.config["DATABASE"]):
        init_db(app.config["DATABASE"], reset=False)
    return app


def main():
    parser = argparse.ArgumentParser(description="Run the ShopLab e-commerce testbed.")
    parser.add_argument("--mode", choices=MODES, default=os.environ.get("SHOPLAB_MODE", "vulnerable"))
    parser.add_argument("--port", type=int, default=None,
                        help="default: 5001 (vulnerable) / 5002 (patched)")
    parser.add_argument("--reset-db", action="store_true", help="re-create and re-seed the database first")
    args = parser.parse_args()

    port = args.port or (5001 if args.mode == "vulnerable" else 5002)
    if args.reset_db:
        init_db(db_path_for_mode(args.mode), reset=True)

    print("=" * 70, file=sys.stderr)
    print(f" ShopLab testbed - {args.mode.upper()} mode - http://127.0.0.1:{port}", file=sys.stderr)
    if args.mode == "vulnerable":
        print(" WARNING: deliberately vulnerable. Bound to 127.0.0.1 only.", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    # Always bind to localhost and never enable the Werkzeug debugger.
    create_app(args.mode).run(host="127.0.0.1", port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
