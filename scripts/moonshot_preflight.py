"""Bounded Moonshot CN credential/model preflight; no raw error bodies or secrets exported."""
import http.client
import json
import os
from pathlib import Path
import re
import stat
import time
import urllib.error
import urllib.request

MODEL_URL = "https://api.moonshot.cn/v1/models"
SUPPORTED_MODEL = "kimi-k2.6"
REQUEST_PROFILE = "moonshot-k2.6-instant-v1"


class PreflightError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PreflightError("invalid_model_list")
        result[key] = value
    return result


def _constant(value):
    raise PreflightError("invalid_model_list")


def load_credential(path=None, environment=None):
    environment = os.environ if environment is None else environment
    if path is None and environment.get("MOONSHOT_API_KEY"):
        key = environment["MOONSHOT_API_KEY"]
    else:
        path = path or environment.get("MOONSHOT_API_KEY_FILE")
        if not path:
            raise PreflightError("missing_credentials")
        try:
            with os.fdopen(os.open(Path(path), os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as source:
                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
                    raise PreflightError("credential_file_not_private")
                data = source.read(4099)
            key = data.decode("ascii").removesuffix("\n").removesuffix("\r")
        except (OSError, ValueError, UnicodeError):
            raise PreflightError("credential_file_unavailable") from None
    if not isinstance(key, str) or not 16 <= len(key) <= 4096 or any(not 33 <= ord(c) <= 126 for c in key):
        raise PreflightError("invalid_credential_format")
    return key


def list_models(key, opener=None):
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(MODEL_URL, headers={"Authorization": "Bearer " + key, "Accept": "application/json"})
    deadline = time.monotonic() + 10
    try:
        try:
            response = opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            if response.status != 200:
                code = {401: "provider_unauthorized", 403: "provider_forbidden", 429: "provider_rate_limited"}.get(response.status, "model_discovery_failed")
                raise PreflightError(code)
            if response.headers.get_content_type() != "application/json":
                raise PreflightError("invalid_model_list")
            data = bytearray()
            while True:
                if time.monotonic() >= deadline:
                    raise PreflightError("model_discovery_timeout")
                chunk = response.read1(min(4096, 65537 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > 65536:
                    raise PreflightError("model_list_limit")
        if time.monotonic() >= deadline:
            raise PreflightError("model_discovery_timeout")
        body = json.loads(data, object_pairs_hook=_object, parse_constant=_constant)
        rows = body.get("data") if isinstance(body, dict) else None
        if not isinstance(rows, list) or len(rows) > 1000:
            raise PreflightError("invalid_model_list")
        ids = []
        for row in rows:
            name = row.get("id") if isinstance(row, dict) else None
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", name):
                raise PreflightError("invalid_model_list")
            ids.append(name)
        return sorted(set(ids))
    except PreflightError:
        raise
    except (TimeoutError,):
        raise PreflightError("model_discovery_timeout") from None
    except (OSError, ValueError, RecursionError, urllib.error.URLError, http.client.HTTPException):
        raise PreflightError("model_discovery_failed") from None


def require_model(model, models):
    # Protected projection strips reasoning_content. Models requiring preserved
    # reasoning need a separate protected continuation design before support.
    if model != SUPPORTED_MODEL:
        raise PreflightError("unsupported_model_profile")
    if model not in models:
        raise PreflightError("compatible_model_unavailable")
    return REQUEST_PROFILE
