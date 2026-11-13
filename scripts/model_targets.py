"""Validated loopback model targets; declarations are not verified model provenance."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit


def load_target(path):
    raw = Path(path).read_bytes()
    if len(raw) > 8192:
        raise ValueError("target file exceeds 8 KiB")
    target = json.loads(raw)
    required = {"base_url", "model", "revision", "quantization", "chat_template_sha256"}
    if not isinstance(target, dict) or not required <= target.keys() or target.keys() - required - {"api_key_env"}:
        raise ValueError("target fields do not match the local model contract")
    for name in required:
        if not isinstance(target[name], str) or not 1 <= len(target[name]) <= 300 or any(ord(char) < 32 for char in target[name]):
            raise ValueError("invalid target field")
    if not re.fullmatch(r"[a-f0-9]{64}", target["chat_template_sha256"]):
        raise ValueError("chat template SHA256 must be declared")
    endpoint = urlsplit(target["base_url"])
    if (endpoint.scheme not in ("http", "https") or endpoint.username or endpoint.password or
            endpoint.query or endpoint.fragment or endpoint.path.rstrip("/") != "/v1" or not endpoint.port or
            not ipaddress.ip_address(endpoint.hostname).is_loopback):
        raise ValueError("target must be an explicit loopback IP and port with /v1 path")
    variable = target.get("api_key_env")
    if variable is not None and (not isinstance(variable, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,79}", variable)):
        raise ValueError("invalid credential environment variable")
    key = os.environ.get(variable, "") if variable else "synthetic-local-model-no-auth"
    if not key or len(key) > 4096 or any(ord(char) < 33 or ord(char) > 126 for char in key):
        raise ValueError("local model credential is missing or invalid")
    public = {name: target[name] for name in required - {"base_url"}}
    public.update(provenance="operator_declared_not_verified", configuration_sha256=hashlib.sha256(raw).hexdigest())
    return target, public, key
