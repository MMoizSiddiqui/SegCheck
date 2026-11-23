"""Plain-language error pages and JSON errors.

Every error a person can hit in the browser gets a page that says what happened, why it
usually happens and what to do next. API endpoints get the same explanation as
JSON. Unexpected crashes are logged with a short reference number to
<data folder>/logs/errors.log; the page shows the reference, never a stack trace.
"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone
from pathlib import Path

from flask import current_app, jsonify, render_template, request
from flask_wtf.csrf import CSRFError
from werkzeug.exceptions import HTTPException

EXPLANATIONS = {
    400: ("This request could not be used",
          "The form or link was incomplete, expired, or sent twice.",
          ["Go back, reload the page and try again.",
           "Previews and forms expire after a few minutes for safety; open them again."]),
    401: ("Please sign in", "This page needs a signed-in account.", ["Sign in and try again."]),
    403: ("Not allowed", "Your account or this client may not do this.",
          ["Check you are signed in with the right account.", "Sign out and in again; your session may have ended."]),
    404: ("Not found", "This page or record does not exist, or it belongs to another account.",
          ["Check the address.", "Use the menu on the left to find the record."]),
    405: ("Not possible here", "This address does not accept that kind of request.", ["Use the buttons in the app instead of typing the address."]),
    409: ("Cannot do that right now",
          "The stored policy or configuration changed, is incomplete, or did not pass its integrity check.",
          ["Reload the page and review it again.",
           "Check New audit: Step 1 (where you are), Step 2 (targets) and Step 3 (firewall).",
           "If a stored record fails its integrity check, restore the data folder from the backups folder."]),
    413: ("Too large", "What was sent is bigger than SegCheck accepts.", ["Upload a smaller file (policies are small YAML/JSON files)."]),
    429: ("Too many attempts", "Sign-in is paused briefly after repeated failures, to stop password guessing.",
          ["Wait a few minutes, then try again."]),
    500: ("SegCheck hit a problem it did not expect",
          "This is a fault inside SegCheck, not something you did wrong. Your data is safe: nothing was half-saved, the action "
          "was simply undone.",
          ["Click Go back and try the same thing once more. Many problems are one-off and do not come back.",
           "If it fails again in the same place, it is a bug in SegCheck. Report it to whoever looks after SegCheck "
           "(for the public version: open an issue on its GitHub page) and include the reference below.",
           "Meanwhile you can keep working on other pages; only this one action failed."]),
    503: ("Temporarily unavailable", "A required part (such as network discovery) is not available right now.", ["Wait a moment and try again."]),
}


def _wants_json():
    path = request.path or ""
    if path.startswith("/api/") or path.endswith(("/status", ".json")):
        return True
    best = request.accept_mimetypes.best_match(["application/json", "text/html"])
    return best == "application/json" and request.accept_mimetypes[best] > request.accept_mimetypes["text/html"]


def _log_incident(error):
    incident = secrets.token_hex(4).upper()
    current_app.logger.error("Unexpected error %s on %s %s", incident, request.method, request.path, exc_info=error)
    data_dir = current_app.config.get("SEGCHECK_DATA_DIR")
    if data_dir:
        try:
            logs = Path(data_dir) / "logs"
            logs.mkdir(exist_ok=True)
            handler = logging.FileHandler(logs / "errors.log", encoding="utf-8")
            record = logging.LogRecord("segcheck", logging.ERROR, __file__, 0,
                                       f"{datetime.now(timezone.utc).isoformat()} incident {incident} on "
                                       f"{request.method} {request.path}", None, (type(error), error, error.__traceback__))
            handler.setFormatter(logging.Formatter("%(message)s"))
            handler.emit(record)
            handler.close()
        except OSError:
            pass
    return incident


def render_error(code, detail=None, incident=None):
    title, meaning, steps = EXPLANATIONS.get(code, EXPLANATIONS[500 if code >= 500 else 400])
    if _wants_json():
        response = jsonify({"error": detail or title, "title": title, "meaning": meaning, "what_to_do": steps,
                            "status": code, **({"reference": incident} if incident else {})})
    else:
        referrer = request.referrer or ""
        back_url = referrer if referrer.startswith(request.host_url) and referrer != request.url else None
        response = current_app.make_response(render_template("errors/error.html", code=code, title=title, meaning=meaning,
                                                             steps=steps, detail=detail, incident=incident, back_url=back_url))
    response.status_code = code
    response.headers["Cache-Control"] = "no-store"
    return response


def register_error_pages(app):
    @app.errorhandler(CSRFError)
    def csrf_error(error):
        return render_error(400, "This form expired or did not come from SegCheck itself (security check: every form "
                                 "carries a one-time token tied to your sign-in). This usually happens when the page was "
                                 "left open while SegCheck restarted or your session ended. Reload the page (sign in if "
                                 "asked) and submit it again; nothing was changed.")

    @app.errorhandler(HTTPException)
    def http_error(error):
        if error.code in (301, 302, 303, 307, 308) or error.code is None:
            return error
        detail = error.description if error.description and error.description != type(error).description else None
        response = render_error(error.code, detail)
        if error.code == 405 and getattr(error, "valid_methods", None):
            response.headers["Allow"] = ", ".join(error.valid_methods)
        return response

    @app.errorhandler(Exception)
    def unexpected_error(error):
        if isinstance(error, HTTPException):
            return http_error(error)
        if app.config.get("TESTING") and app.config.get("SEGCHECK_PROPAGATE_ERRORS", True):
            raise error  # tests see the real exception
        try:
            from segcheck_web.extensions import db
            db.session.rollback()
        except Exception:  # noqa: BLE001 (best effort while handling an error)
            pass
        return render_error(500, incident=_log_incident(error))
