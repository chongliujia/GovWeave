"""Versioned, bounded task checks. No model calls or response text in results."""
import re

VERSION = "task-facts-v1"
MAX_BYTES = 8192
_TIME = r"[0-9]{1,2}:[0-9]{2}\s*(?:a\.?m\.?|p\.?m\.?)?"
_ZONE = r"(?:UTC|GMT)(?:[+-][0-9]{1,2}(?::[0-9]{2})?)?|Z|CET|CEST|EST|EDT|PST|PDT|JST|IST|CST"
_INTERVAL = re.compile(rf"(?:(?P<before>{_ZONE})\s+)?(?P<start>{_TIME})\s*(?:-|–|—|to|until|至)\s*(?P<end>{_TIME})(?:\s*(?P<after>{_ZONE}))?", re.I)
_CLOCK = re.compile(r"([0-9]{1,2}):([0-9]{2})\s*(a\.?m\.?|p\.?m\.?)?", re.I)
_EMAIL = re.compile(r"([A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64})@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
_HOURS_PREFIX = re.compile(r"^(?:(?:office opening interval|office hours|opening hours)\s*(?::|are)|the office is open from|营业时间\s*(?::|是))\s*", re.I)
_EMAIL_PREFIX = re.compile(r"^(?:(?:published billing email|email|邮箱)\s*:|the published billing email is)\s*", re.I)
_WIDTH = str.maketrans("０１２３４５６７８９：", "0123456789:")


def _surface(text):
    # Only paired inline presentation markers. Extra prose is retained and must
    # match the entire grammar; negated, conditional or quoted claims do not pass
    # merely because a correct fact appears somewhere in them.
    text = text.strip()
    for pattern in (r"\*\*([^*\r\n]+)\*\*", r"__([^_\r\n]+)__", r"`([^`\r\n]+)`"):
        text = re.sub(pattern, r"\1", text, count=8)
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"[.。]$", "", text).strip()
    if len(text) > 1 and (text[0], text[-1]) in (("\"", "\""), ("'", "'")):
        text = text[1:-1].strip()
    return text


def _clock(text):
    match = _CLOCK.fullmatch(text)
    hour, minute = int(match[1]), int(match[2])
    suffix = (match[3] or "").lower().replace(".", "")
    if minute > 59 or hour > 23 or suffix and not 1 <= hour <= 12:
        return None, bool(suffix)
    if suffix:
        hour = hour % 12 + (12 if suffix == "pm" else 0)
    return hour * 60 + minute, bool(suffix)


def _zone(text):
    upper = text.upper()
    if upper in ("UTC", "GMT", "Z"):
        return "UTC"
    match = re.fullmatch(r"(?:UTC|GMT)([+-])([0-9]{1,2})(?::([0-9]{2}))?", upper)
    if match:
        hour, minute = int(match[2]), int(match[3] or 0)
        if hour > 14 or minute > 59 or hour == 14 and minute:
            return None
        return "UTC" if hour == minute == 0 else "different_zone"
    return "different_zone"


def _email(text):
    match = _EMAIL.fullmatch(text)
    if not match or len(text) > 254:
        return None
    local, domain = match.groups()
    if local.startswith(".") or local.endswith(".") or ".." in local:
        return None
    labels = domain.split(".")
    if any(len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels) or not re.fullmatch(r"[A-Za-z]{2,63}", labels[-1]):
        return None
    return local, domain.lower()


def check_fact(spec, answer):
    """Return fixed metadata only; parsed facts live only in this call."""
    kind = spec.get("kind") if isinstance(spec, dict) else None
    expected = spec.get("expected") if isinstance(spec, dict) else None
    result = {"version": VERSION, "check": kind if kind in ("hours", "email", "literal") else "unsupported", "result": "unknown", "reason": "invalid_expectation"}

    def verdict(state, reason):
        return dict(result, result=state, reason=reason)

    if not isinstance(expected, dict) or not isinstance(answer, str):
        return result
    if len(answer) > MAX_BYTES:
        return verdict("unknown", "answer_limit")
    try:
        if len(answer.encode("utf-8")) > MAX_BYTES:
            return verdict("unknown", "answer_limit")
    except UnicodeError:
        return verdict("unknown", "invalid_text")
    if kind == "hours":
        if set(expected) != {"start_minutes", "end_minutes", "zone"} or expected["zone"] != "UTC" or any(type(expected[k]) is not int or not 0 <= expected[k] < 1440 for k in ("start_minutes", "end_minutes")):
            return result
        body = _HOURS_PREFIX.sub("", _surface(answer.translate(_WIDTH)), count=1)
        match = _INTERVAL.fullmatch(body)
        if not match:
            return verdict("unknown", "unsupported_answer")
        start, am = _clock(match["start"])
        end, pm = _clock(match["end"])
        if start is None or end is None:
            return verdict("unknown", "invalid_time")
        if am != pm:
            return verdict("unknown", "ambiguous_time_format")
        if match["before"] and match["after"]:
            return verdict("unknown", "ambiguous_timezone")
        zone = match["before"] or match["after"]
        if not zone:
            return verdict("unknown", "timezone_missing")
        zone = _zone(zone)
        if zone is None:
            return verdict("unknown", "invalid_timezone")
        if zone != expected["zone"]:
            return verdict("mismatch", "timezone_mismatch")
        if (start, end) != (expected["start_minutes"], expected["end_minutes"]):
            return verdict("mismatch", "time_value_mismatch")
        return verdict("match", "facts_match")
    if kind == "email":
        if set(expected) != {"address"} or not isinstance(expected["address"], str) or _email(expected["address"]) is None:
            return result
        body = _EMAIL_PREFIX.sub("", _surface(answer).replace("邮箱：", "邮箱:"), count=1)
        if body.startswith("<") and body.endswith(">"):
            body = body[1:-1]
        link = re.fullmatch(r"\[([^\[\]]+)\]\(mailto:([^()]+)\)", body, re.I)
        if link:
            if _email(link[1]) is None or _email(link[1]) != _email(link[2]):
                return verdict("unknown", "link_target_mismatch")
            body = link[1]
        parsed = _email(body)
        if parsed is None:
            return verdict("unknown", "unsupported_answer")
        if parsed != _email(expected["address"]):
            return verdict("mismatch", "email_value_mismatch")
        return verdict("match", "facts_match")
    if kind == "literal" and set(expected) == {"text"} and isinstance(expected["text"], str) and 0 < len(expected["text"]) <= 256:
        # Explicit historical fallback for unsupported fact types, not a claim
        # that a contained topic label is a semantically correct answer.
        return verdict("match", "legacy_literal_match") if expected["text"] in answer else verdict("unknown", "legacy_literal_missing")
    return result


def assess_task(spec, row, answer):
    result = {"version": VERSION, "check": spec["kind"] if spec else "unsupported", "result": "not_evaluated", "reason": "execution_unknown", "completed": None, "diagnosis": "execution_unknown"}
    if not row.get("audit_complete") or row["status"] not in ("completed", "blocked"):
        return result
    if row["status"] == "blocked":
        return dict(result, reason="gateway_blocked", completed=False, diagnosis="gateway_blocked")
    if not row.get("expected_read_returned"):
        return dict(result, reason="expected_read_missing", completed=False, diagnosis="missing_expected_read")
    result.update(check_fact(spec, answer))
    if result["result"] == "match":
        result.update(completed=True, diagnosis="literal_match" if row.get("task_completed") else "format_equivalent")
    elif result["result"] == "mismatch":
        result.update(completed=False, diagnosis="fact_mismatch")
    else:
        result["diagnosis"] = "intervention_observed" if row.get("intervention") else "grading_unknown"
    return result
