"""Standard-library reference integration for GovWeave's read-tool API.

Copy/adapt this example into an application backend or Agent executor. It is
not a separately distributed SDK. Configuration and application identity stay
outside model-controlled arguments. No retries or direct-provider fallback.
"""

from dataclasses import dataclass, field
import http.client
import json
import math
import re
import time
import urllib.error
import urllib.parse
import urllib.request


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")
_REQUEST_ID = re.compile(r"req_[A-Za-z0-9_-]{22}\Z")
_MAX_RESPONSE = 65536
_GATEWAY_ERRORS = {
    "invalid_api_key": 401,
    "invalid_trace_context": 400,
    "trace_unavailable": 503,
    "tool_not_allowed": 403,
    "tool_output_blocked": 403,
    "tool_instruction_blocked": 403,
    "tool_instruction_unavailable": 502,
    "content_output_blocked": 403,
    "content_output_unavailable": 502,
    "invalid_tool_request": 400,
    "request_too_large": 413,
    "unsupported_media_type": 415,
    "audit_unavailable": 503,
    "credential_unavailable": 503,
    "gateway_busy": 429,
    "upstream_timeout": 504,
    "client_cancelled": 499,
    "upstream_unreachable": 502,
    "upstream_error": 502,
    "invalid_upstream_response": 502,
    "response_too_large": 502,
}
_REASONS = set(_GATEWAY_ERRORS) | {
    "resource_grant_allowed", "credential_patterns_not_observed",
    "credential_patterns_observed", "content_patterns_observed", "content_redacted",
    "instruction_patterns_observed",
    "instruction_review_applied",
}


class ToolCallError(Exception):
    """Fixed local code and safe correlation metadata; no raw response or URL."""

    def __init__(self, code, request_id="", http_status=0):
        self.code = code
        self.request_id = request_id
        self.http_status = http_status
        super().__init__("Governed tool call failed: " + code)


@dataclass(frozen=True)
class ToolResult:
    # Avoid accidental content disclosure through ordinary repr/logging.
    text: str = field(repr=False)
    request_id: str
    governance: dict


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _constant(_):
    raise ValueError("unsupported JSON constant")


def _output_policy(value):
    fields = {"id", "revision", "detector_version", "mode", "result", "state", "reason", "categories", "matched_categories", "matched_rules", "check_duration_us"}
    if not isinstance(value, dict) or not fields <= value.keys() or value.keys() - fields - {"redaction", "public_email_exceptions"}:
        return False
    if value["id"] != "sensitive-output" or value["detector_version"] not in ("sensitive-text-v1", "sensitive-text-v2", "sensitive-text-v3") or value["mode"] not in ("block", "observe", "redact"):
        return False
    if type(value["revision"]) is not int or not 1 <= value["revision"] <= 127 or type(value["check_duration_us"]) is not int or value["check_duration_us"] < 0:
        return False
    if value["state"] not in ("observed", "not_observed", "unknown") or value["result"] not in ("allow", "observe", "block", "error", "redact", "redacted"):
        return False
    reasons = ("patterns_observed", "patterns_not_observed", "input_limit", "invalid_utf8", "finding_limit", "output_unavailable", "stream_unsupported", "redaction_unavailable")
    if value["detector_version"] == "sensitive-text-v3":
        reasons += ("encoding_limit",)
    if value["reason"] not in reasons:
        return False
    rules = ("private_key", "api_key", "email_address", "cn_mobile_phone")
    if value["detector_version"] in ("sensitive-text-v2", "sensitive-text-v3"):
        rules += tuple("normalized_" + rule for rule in rules)
    if value["detector_version"] == "sensitive-text-v3":
        rules += ("formatted_email_address",)
        rules += tuple("base64_" + rule for rule in rules)
    for name, options in (("categories", ("credential", "email", "phone")), ("matched_categories", ("credential", "email", "phone")), ("matched_rules", rules)):
        values = value[name]
        if not isinstance(values, list) or len(values) > len(options) or any(item not in options for item in values) or len(set(values)) != len(values):
            return False
    if not value["categories"] or any(item not in value["categories"] for item in value["matched_categories"]):
        return False
    if "public_email_exceptions" in value and (type(value["public_email_exceptions"]) is not int or not 1 <= value["public_email_exceptions"] <= 32 or value["state"] != "observed" or "email" not in value["categories"]):
        return False
    redaction = value.get("redaction")
    if value["result"] == "redacted":
        if (not isinstance(redaction, dict) or set(redaction) != {"version", "scope", "replacements", "check_duration_us"} or
                redaction["version"] != "sensitive-redaction-v1" or redaction["scope"] not in ("matched_spans", "full_output") or
                type(redaction["replacements"]) is not int or not 1 <= redaction["replacements"] <= 32 or
                type(redaction["check_duration_us"]) is not int or redaction["check_duration_us"] < 0):
            return False
        full = "credential" in value["matched_categories"]
        if redaction["scope"] != ("full_output" if full else "matched_spans") or full and redaction["replacements"] != 1:
            return False
        return value["mode"] == "redact" and value["state"] == "observed" and value["reason"] == "patterns_observed" and bool(value["matched_categories"]) and bool(value["matched_rules"])
    if "redaction" in value:
        return False
    if value["result"] == "error":
        return value["state"] == "unknown"
    if value["state"] == "unknown":
        return False
    if value["result"] == "allow":
        return not value["matched_categories"] and not value["matched_rules"]
    return value["state"] == "observed" and bool(value["matched_categories"]) and bool(value["matched_rules"]) and value["result"] == value["mode"]


def _instruction_policy(value):
    fields = {"version", "mode", "state", "rule_ids", "duration_us", "decision"}
    if not isinstance(value, dict) or not fields <= value.keys() or value.keys() - fields - {"review"} or value["version"] not in ("tool-instructions-v1", "tool-instructions-v2") or value["mode"] not in ("block", "observe"):
        return False
    if type(value["duration_us"]) is not int or value["duration_us"] < 0:
        return False
    rules = value["rule_ids"]
    supported = ("task_override", "authority_spoof", "role_delimiter") + (("answer_manipulation",) if value["version"] == "tool-instructions-v2" else ())
    if not isinstance(rules, list) or len(rules) > len(supported) or any(rule not in supported for rule in rules) or len(set(rules)) != len(rules):
        return False
    exempted = []
    if "review" in value:
        review = value["review"]
        if not isinstance(review, dict) or set(review) != {"version", "state", "exempted_rule_ids"} or review["version"] != "exact-instruction-review-v1" or review["state"] not in ("matched", "mismatch", "unavailable"):
            return False
        exempted = review["exempted_rule_ids"]
        if not isinstance(exempted, list) or len(exempted) > len(rules) or any(rule not in supported or rule not in rules for rule in exempted) or len(set(exempted)) != len(exempted):
            return False
        if (value["state"] == "unknown") != (review["state"] == "unavailable") or (review["state"] != "matched" and exempted):
            return False
    if value["state"] == "unknown":
        return not rules and value["decision"] == "error"
    if value["state"] == "not_observed":
        return not rules and value["decision"] == "allow"
    return value["state"] == "observed" and bool(rules) and value["decision"] == ("allow" if len(exempted) == len(rules) else value["mode"])


def _governance(value):
    required = {"policy_version", "ruleset_version", "tool_revision", "action",
                "authorization", "data_sensitivity", "content", "decision", "reasons"}
    optional = {"tool_id", "snapshot_sha256", "output_mode", "output_policy", "instruction_policy"}
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        return False
    if value["policy_version"] != "read-tool-governance-v1" or value["ruleset_version"] != "credentials-v1" or value["action"] != "read":
        return False
    if type(value["tool_revision"]) is not int or not 0 <= value["tool_revision"] <= 128:
        return False
    if value["authorization"] not in ("unknown", "allowed", "denied") or value["data_sensitivity"] not in ("unknown", "public", "internal", "restricted"):
        return False
    if value["decision"] not in ("allow", "observe", "block", "redact"):
        return False
    if "tool_id" in value and (not isinstance(value["tool_id"], str) or not re.fullmatch(r"tool_[A-Za-z0-9_-]{16}", value["tool_id"])):
        return False
    if "snapshot_sha256" in value and (not isinstance(value["snapshot_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["snapshot_sha256"])):
        return False
    if "output_mode" in value and value["output_mode"] not in ("block", "observe"):
        return False
    if "output_policy" in value and not _output_policy(value["output_policy"]):
        return False
    if "instruction_policy" in value and not _instruction_policy(value["instruction_policy"]):
        return False
    content = value["content"]
    if not isinstance(content, dict) or set(content) != {"state", "rule_ids"} or content["state"] not in ("unknown", "observed", "not_observed"):
        return False
    rules = content["rule_ids"]
    if not isinstance(rules, list) or len(rules) > 2 or any(rule not in ("private_key", "api_key") for rule in rules) or len(set(rules)) != len(rules):
        return False
    if (content["state"] == "observed") != bool(rules):
        return False
    reasons = value["reasons"]
    if not isinstance(reasons, list) or not 1 <= len(reasons) <= 2 or any(not isinstance(reason, str) or reason not in _REASONS for reason in reasons):
        return False
    return True


def _parse_tool_response(data, status, header_id):
    """Parse bounded gateway bytes without performing I/O; shared by clients."""
    if len(data) > _MAX_RESPONSE:
        raise ToolCallError("response_limit", http_status=status)
    try:
        result = json.loads(data.decode("utf-8"), object_pairs_hook=_object, parse_constant=_constant)
    except (ValueError, RecursionError):
        raise ToolCallError("invalid_response") from None
    if not isinstance(result, dict):
        raise ToolCallError("invalid_response", http_status=status)
    request_id = result.get("request_id")
    if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id) or request_id != header_id:
        raise ToolCallError("invalid_response", http_status=status)
    governance = result.get("governance")
    if not _governance(governance):
        raise ToolCallError("invalid_response", request_id, status)
    if status != 200:
        error = result.get("error")
        if (set(result) != {"request_id", "governance", "error"} or governance["decision"] != "block" or
                not isinstance(error, dict) or error.get("type") != "tool_governance_error" or
                not isinstance(error.get("code"), str) or _GATEWAY_ERRORS.get(error["code"]) != status):
            raise ToolCallError("invalid_response", request_id, status)
        raise ToolCallError(error["code"], request_id, status)
    text = result.get("text")
    valid = (set(result) == {"request_id", "text", "governance"} and isinstance(text, str) and
             governance["authorization"] == "allowed" and governance["decision"] in ("allow", "observe", "redact") and
             governance["tool_revision"] > 0 and all(name in governance for name in ("tool_id", "snapshot_sha256", "output_mode")))
    if valid:
        try:
            valid = len(text.encode("utf-8")) <= 8192
        except UnicodeError:
            valid = False
    if valid:
        output_policy = governance.get("output_policy")
        output_allowed = output_policy is None or output_policy["result"] in ("allow", "observe", "redacted")
        legacy_observed = governance["content"]["state"] == "observed"
        any_observed = legacy_observed or (output_policy is not None and output_policy["result"] == "observe")
        instruction_policy = governance.get("instruction_policy")
        output_allowed = output_allowed and (instruction_policy is None or instruction_policy["decision"] in ("allow", "observe"))
        any_observed = any_observed or (instruction_policy is not None and instruction_policy["decision"] == "observe")
        expected_decision = "redact" if output_policy is not None and output_policy["result"] == "redacted" else ("observe" if any_observed else "allow")
        valid = (output_allowed and governance["content"]["state"] != "unknown" and
                 (not legacy_observed or governance["output_mode"] == "observe") and
                 governance["decision"] == expected_decision)
    if not valid:
        raise ToolCallError("invalid_response", request_id, status)
    return ToolResult(text=text, request_id=request_id, governance=governance)


class GovernedToolClient:
    def __init__(self, root_url, api_key, alias, timeout=5, allow_insecure_http=False):
        try:
            url = urllib.parse.urlsplit(root_url)
            valid = (isinstance(root_url, str) and len(root_url) <= 2048 and
                     not any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in root_url) and
                     url.scheme in ("http", "https") and url.hostname and
                     url.path in ("", "/") and url.username is None and url.password is None and
                     not any(character in root_url for character in "?#\\") and
                     (url.scheme == "https" or allow_insecure_http is True))
            # Validate port syntax/range without opening any connection.
            url.port
            valid = valid and isinstance(alias, str) and _IDENTIFIER.fullmatch(alias)
            valid = valid and isinstance(api_key, str) and re.fullmatch(r"gw_app_[A-Za-z0-9_-]{43}", api_key)
            valid = valid and type(timeout) in (int, float) and math.isfinite(timeout) and 1 <= timeout <= 60
            if not valid:
                raise ValueError("invalid client configuration")
        except (ValueError, TypeError, AttributeError):
            raise ToolCallError("invalid_configuration") from None
        self._endpoint = root_url.rstrip("/") + "/v1/tools/" + alias + "/invoke"
        self._key = api_key
        self._timeout = timeout
        # Explicit connection: no environment proxy, redirect or cookie jar.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def execute(self, arguments):
        """Agent executor hook. Only the resource identifier is model-supplied."""
        if not isinstance(arguments, dict) or set(arguments) != {"resource_id"}:
            raise ToolCallError("invalid_arguments")
        return self.invoke(arguments["resource_id"])

    def invoke(self, resource_id):
        if not isinstance(resource_id, str) or not _IDENTIFIER.fullmatch(resource_id):
            raise ToolCallError("invalid_arguments")
        payload = json.dumps({"resource_id": resource_id}, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(self._endpoint, data=payload, method="POST", headers={
            "Authorization": "Bearer " + self._key,
            "Content-Type": "application/json", "Accept": "application/json",
        })
        deadline = time.monotonic() + self._timeout
        try:
            try:
                response = self._opener.open(request, timeout=self._timeout)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                status = response.status
                header_id = response.headers.get("X-Request-ID", "")
                if response.headers.get_content_type() != "application/json":
                    raise ToolCallError("invalid_response", http_status=status)
                data = bytearray()
                while True:
                    if time.monotonic() > deadline:
                        raise ToolCallError("transport_timeout")
                    chunk = response.read1(min(4096, _MAX_RESPONSE + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                    if len(data) > _MAX_RESPONSE:
                        raise ToolCallError("response_limit", http_status=status)
                if time.monotonic() > deadline:
                    raise ToolCallError("transport_timeout")
        except ToolCallError:
            raise
        except TimeoutError:
            raise ToolCallError("transport_timeout") from None
        except (OSError, urllib.error.URLError, http.client.HTTPException):
            raise ToolCallError("transport_error") from None
        except (ValueError, RecursionError):
            raise ToolCallError("invalid_response") from None
        return _parse_tool_response(data, status, header_id)
