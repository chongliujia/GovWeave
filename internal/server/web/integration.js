import { t } from "/i18n.js";

const el = id => document.getElementById(id);
const requestID = /^req_[A-Za-z0-9_-]{22}$/;
const traceID = /^(?!0{32}$)[0-9a-f]{32}$/;
const spanID = /^(?!0{16}$)[0-9a-f]{16}$/;
const modes = { disabled: "Disabled", observe: "Observe", block: "Block", redact: "Redact" };
const messages = {
  idle: "Choose an application and model, then enter its application key.",
  checking: "Checking local configuration. No model request is sent.",
  configured: "Configuration checked. Model inference has not been tested.",
  running: "Sending one synthetic model request, then checking its audit record…",
  completed: "One model request completed and its audit record matched.",
  blocked: "The gateway blocked this request. Review the recorded decision.",
  failed: "The request failed. Review its HTTP status and request record.",
  unknown: "The result could not be verified. A request may already have reached the provider.",
  invalid_key: "Enter the selected application's key, not an administrator password or provider key.",
  authentication: "The application key is invalid or revoked. Your administrator session is unchanged.",
  wrong_application: "This key belongs to another application. No model request was sent.",
  denied: "This key cannot use the selected model. No model request was sent.",
  changed: "Configuration changed. Refresh the console before verifying again.",
  audit_unavailable: "Request recording is unavailable. No model request was sent.",
  preflight_unknown: "Configuration could not be verified. No model request was sent.",
  receipt_unknown: "The response or audit receipt could not be verified. Inspect request logs before trying again.",
};

function element(tag, text) {
  const value = document.createElement(tag);
  if (text !== undefined) value.textContent = text;
  return value;
}

function shellQuote(value) { return "'" + value.replaceAll("'", "'\"'\"'") + "'"; }

function validCheck(value) {
  const policy = (p, output) => p && typeof p.applies === "boolean" && Number.isSafeInteger(p.revision) && p.revision >= 0 &&
    (output ? ["disabled", "observe", "block", "redact"] : ["disabled", "observe", "block"]).includes(p.mode);
  return value?.schema_version === 1 && typeof value.application_id === "string" && typeof value.model === "string" &&
    Number.isSafeInteger(value.configuration_revision) && value.configuration_revision >= 0 &&
    value.upstream_contacted === false && value.inference === "not_tested" &&
    value.checks?.model_access === "allowed" && typeof value.checks.audit_available === "boolean" &&
    policy(value.checks.input_policy, false) && policy(value.checks.output_policy, true) &&
    value.supported?.chat_completions === true && typeof value.supported.streaming === "boolean" &&
    value.supported.tool_governance_requires_separate_integration === true;
}

// Keep response text transient and bounded. It never becomes UI content or storage.
async function jsonResponse(response, limit) {
  if ((response.headers.get("Content-Type") || "").split(";", 1)[0].trim().toLowerCase() !== "application/json" || !response.body) throw new Error("invalid_response");
  const reader = response.body.getReader(), chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw new Error("response_limit");
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

function completeText(data) {
  const choice = data?.choices?.[0];
  return Array.isArray(data?.choices) && data.choices.length === 1 && choice?.index === 0 &&
    choice.finish_reason === "stop" && choice.message?.role === "assistant" &&
    typeof choice.message.content === "string" && choice.message.content.trim().length > 0 &&
    (choice.message.tool_calls == null || Array.isArray(choice.message.tool_calls) && choice.message.tool_calls.length === 0) &&
    choice.message.function_call == null;
}

export function createIntegrationConsole({ getState, getInstance, request, openRecords }) {
  let epoch = 0, controller = null, busy = false, fingerprint = "";
  let result = { state: "idle", code: "idle" };

  function selected() {
    const state = getState();
    const app = state.applications.find(value => value.id === el("example-app").value && !value.revoked);
    const connection = app && state.connections.find(value => value.alias === el("example-model").value && value.enabled && app.allowed_connections.includes(value.id));
    return { app, connection, revision: state.revision };
  }

  function controls() {
    const { app, connection } = selected();
    const canCheck = !!(app && connection && el("integration-key").value);
    el("integration-key").disabled = busy || !(app && connection);
    el("integration-check").disabled = busy || !canCheck;
    el("integration-send").disabled = busy || !canCheck;
    el("integration-records").disabled = busy || !result.applicationID;
    el("integration-result").setAttribute("aria-busy", String(busy));
  }

  function renderResult() {
    const box = el("integration-result");
    box.dataset.state = result.state;
    el("integration-status").textContent = t(messages[result.code] || messages.unknown);
    const fields = el("integration-fields"); fields.replaceChildren();
    const rows = [];
    if (result.preflight) {
      const check = result.preflight;
      const policyLabel = value => value.applies ? t(modes[value.mode]) : value.mode === "disabled" ? t("Disabled") : t("Outside scope");
      rows.push([t("Application identity"), check.application_id], [t("Model alias"), check.model],
        [t("Input policy"), policyLabel(check.checks.input_policy)], [t("Output policy"), policyLabel(check.checks.output_policy)],
        [t("Request recording"), check.checks.audit_available ? t("Available") : t("Unavailable")],
        [t("Streaming for this application"), check.supported.streaming ? t("Available") : t("Unavailable with output protection")]);
    }
    if (result.httpStatus) rows.push([t("HTTP status"), String(result.httpStatus)]);
    if (result.requestID) rows.push([t("Request ID"), result.requestID]);
    if (result.traceID) rows.push([t("Trace ID (client correlation)"), result.traceID]);
    for (const [label, value] of rows) {
      const row = element("div"); row.append(element("dt", label), element("dd", value)); fields.append(row);
    }
    controls();
  }

  function clear() {
    epoch++; controller?.abort(); controller = null; busy = false;
    el("integration-key").value = "";
    result = { state: "idle", code: "idle" };
    renderResult();
  }

  function render() {
    const state = getState(), instance = getInstance();
    const app = state.applications.find(value => value.id === el("example-app").value && !value.revoked);
    const enabled = app ? state.connections.filter(value => value.enabled && app.allowed_connections.includes(value.id)) : [];
    const selector = el("example-model"), previous = selector.value;
    selector.replaceChildren(new Option(t("Select an authorized model"), ""));
    for (const connection of enabled) selector.add(new Option(connection.alias, connection.alias));
    selector.value = enabled.some(value => value.alias === previous) ? previous : enabled[0]?.alias || "";
    selector.disabled = enabled.length === 0;
    const { connection } = selected();
    const nextFingerprint = JSON.stringify([app?.id, connection?.id, state.revision, instance?.public_url]);
    if (nextFingerprint !== fingerprint) { clear(); fingerprint = nextFingerprint; }
    const baseURL = instance?.endpoints?.models?.url;
    el("integration-base-url").textContent = baseURL || t("Available after saving settings");
    el("integration-model-alias").textContent = connection?.alias || t("Select an authorized model");
    el("integration-key-variable").textContent = "GOVWEAVE_API_KEY";
    const canCopy = !!(baseURL && connection);
    const comment = t("# Use an application API key for GOVWEAVE_API_KEY, not the administrator password.");
    let code = comment + "\n" + t("# Save the instance URL, then select an application with an enabled model grant.");
    const language = el("example-language").value;
    el("integration-code-name").textContent = language === "curl" ? "connect.sh" : "connect.py";
    el("integration-code-language").textContent = language === "curl" ? "CURL / HTTP" : "PYTHON / OPENAI SDK";
    if (canCopy) {
      const prompt = "Reply with a short greeting.";
      const timeout = connection.timeout_seconds + 10;
      code = language === "curl" ? [comment,
        `export GOVWEAVE_BASE_URL=${shellQuote(baseURL)}`, `export GOVWEAVE_MODEL=${shellQuote(connection.alias)}`, "",
        'curl --fail-with-body --max-time ' + timeout + ' "${GOVWEAVE_BASE_URL%/}/chat/completions" \\',
        '  -H "Authorization: Bearer $GOVWEAVE_API_KEY" \\', '  -H "Content-Type: application/json" \\',
        `  --data ${shellQuote(JSON.stringify({ model: connection.alias, messages: [{ role: "user", content: prompt }], stream: false }))}`,
      ].join("\n") : ["import os", "from openai import OpenAI", "", comment,
        "client = OpenAI(", `    base_url=${JSON.stringify(baseURL)},`, '    api_key=os.environ["GOVWEAVE_API_KEY"],',
        "    max_retries=0,", `    timeout=${timeout}.0,`, ")", "",
        "response = client.chat.completions.create(", `    model=${JSON.stringify(connection.alias)},`,
        `    messages=[{"role": "user", "content": ${JSON.stringify(prompt)}}],`, "    stream=False,", ")",
        "print(response.choices[0].message.content)",
      ].join("\n");
    }
    el("sdk-example").textContent = code; el("copy-example").disabled = !canCopy;
    renderResult();
  }

  async function publicRequest(path, key, signal, options = {}) {
    return fetch(path, { ...options, method: options.method || "GET", credentials: "omit", redirect: "error", cache: "no-store", signal,
      headers: { Authorization: "Bearer " + key, ...options.headers } });
  }

  async function verify(inference) {
    if (busy) return;
    const { app, connection, revision } = selected();
    if (!app || !connection) return;
    let key = el("integration-key").value;
    el("integration-key").value = "";
    if (!/^gw_app_[A-Za-z0-9_-]{43}$/.test(key)) {
      key = ""; result = { state: "failed", code: "invalid_key" }; renderResult(); return;
    }
    const generation = ++epoch;
    const localController = new AbortController(); controller = localController;
    const timer = setTimeout(() => localController.abort(), (connection.timeout_seconds + 10) * 1000);
    busy = true;
    result = { state: "checking", code: "checking", applicationID: app.id }; renderResult();
    let sent = false;
    try {
      const response = await publicRequest(`/v1/integration/check?model=${encodeURIComponent(connection.alias)}`, key, localController.signal);
      const data = await jsonResponse(response, 16 * 1024);
      if (generation !== epoch) return;
      if (!response.ok) {
        result = { state: "failed", code: response.status === 401 ? "authentication" : response.status === 403 ? "denied" : "preflight_unknown", applicationID: app.id, httpStatus: response.status };
        return;
      }
      if (!validCheck(data)) { result = { state: "unknown", code: "preflight_unknown", applicationID: app.id }; return; }
      if (data.application_id !== app.id) { result = { state: "failed", code: "wrong_application" }; return; }
      if (data.model !== connection.alias || data.configuration_revision !== revision) { result = { state: "unknown", code: "changed", applicationID: app.id }; return; }
      result = { state: "configured", code: "configured", preflight: data, applicationID: app.id };
      if (!data.checks.audit_available) { result.state = "blocked"; result.code = "audit_unavailable"; return; }
      if (!inference) return;
      const bytes = crypto.getRandomValues(new Uint8Array(16));
      const correlation = Array.from(bytes, value => value.toString(16).padStart(2, "0")).join("");
      if (!traceID.test(correlation)) throw new Error("invalid_trace");
      result = { ...result, state: "running", code: "running", traceID: correlation }; renderResult();
      sent = true;
      const response2 = await publicRequest("/v1/chat/completions", key, localController.signal, {
        method: "POST", headers: { "Content-Type": "application/json", "X-GovWeave-Trace-ID": correlation },
        body: JSON.stringify({ model: connection.alias, messages: [{ role: "user", content: "Reply with a short greeting." }], stream: false }),
      });
      key = "";
      if (generation !== epoch) { await response2.body?.cancel(); return; }
      result.httpStatus = response2.status;
      const id = response2.headers.get("X-Request-ID") || "", serverTrace = response2.headers.get("X-GovWeave-Trace-ID"), serverSpan = response2.headers.get("X-GovWeave-Span-ID") || "";
      if (requestID.test(id)) result.requestID = id;
      const body = await jsonResponse(response2, 256 * 1024);
      if (generation !== epoch) return;
      const validReceipt = requestID.test(id) && serverTrace === correlation && spanID.test(serverSpan);
      if (!validReceipt) { result.state = "unknown"; result.code = "receipt_unknown"; return; }
      const validContent = response2.status === 200 && completeText(body);
      const view = await request(`/api/v1/traces/${correlation}?application_id=${encodeURIComponent(app.id)}&limit=16`);
      if (generation !== epoch) return;
      if (localController.signal.aborted) throw new Error("verification_timeout");
      const record = Array.isArray(view.records) && view.records.find(value => value.request_id === id && value.application_id === app.id && value.model === connection.alias &&
        value.operation === "chat.completions" && value.trace?.trace_id === correlation && value.trace?.span_id === serverSpan);
      const samePolicy = record && record.policy_revision === data.configuration_revision &&
        (response2.status !== 200 || !data.checks.input_policy.applies || !!record.content_policy) &&
        (response2.status !== 200 || !data.checks.output_policy.applies || !!record.output_policy) &&
        (!record.content_policy || record.content_policy.revision === data.checks.input_policy.revision) &&
        (!record.output_policy || record.output_policy.revision === data.checks.output_policy.revision);
      if (!record || record.phase !== "finished" || record.http_status !== response2.status) { result.state = "unknown"; result.code = "receipt_unknown"; return; }
      result.record = record;
      if (!samePolicy) { result.state = "unknown"; result.code = "changed"; return; }
      result.state = validContent && record.outcome === "completed" ? "completed" : record.outcome === "blocked" ? "blocked" : response2.status === 200 ? "unknown" : "failed";
      result.code = result.state;
    } catch {
      if (generation === epoch) { result.state = "unknown"; result.code = sent ? "unknown" : "preflight_unknown"; }
    } finally {
      key = ""; clearTimeout(timer);
      if (generation === epoch) { controller = null; busy = false; el("integration-key").value = ""; renderResult(); }
    }
  }

  el("example-app").addEventListener("change", () => { clear(); render(); });
  el("example-model").addEventListener("change", () => { clear(); render(); });
  el("example-language").addEventListener("change", render);
  el("integration-key").addEventListener("input", controls);
  el("integration-check").addEventListener("click", () => verify(false));
  el("integration-send").addEventListener("click", () => verify(true));
  el("integration-records").addEventListener("click", () => {
    if (result.applicationID) openRecords(result.applicationID, result.record);
  });
  window.addEventListener("pagehide", clear);
  return { render, clear };
}
