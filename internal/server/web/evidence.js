import { t, formatDateTime } from "/i18n.js";

const el = id => document.getElementById(id);
const node = (tag, text, className) => {
  const value = document.createElement(tag);
  if (text !== undefined) value.textContent = text;
  if (className) value.className = className;
  return value;
};
const captureModes = { disabled: "Disabled", metadata: "Metadata only", full: "Full capture" };
const objectKinds = { request: "Request input", upstream_request: "Prepared upstream request", upstream_output: "Upstream output", released_output: "Prepared client output" };
const contentStates = {
  retained: "Content retained", metadata_only: "Metadata only", omitted_size: "Content omitted: size limit",
  not_observed: "Content not observed", streaming_not_captured: "Streaming content not captured", unsupported_encoding: "Content encoding not supported",
};
const deliveryStates = { not_observed: "Delivery not observed", withheld: "Withheld", release_prepared: "Prepared; delivery not confirmed", write_completed: "Gateway write completed", write_failed: "Gateway write failed", stream_incomplete: "Stream delivery incomplete" };
const streamEndStates = {
  completed: "Stream completed", incomplete_stream: "Stream ended without complete framing or completion marker",
  invalid_upstream_stream: "Invalid upstream stream frame", upstream_error: "Provider error in stream",
  response_too_large: "Stream exceeded gateway response limit", upstream_timeout: "Upstream stream timed out",
  upstream_unreachable: "Upstream stream read failed", client_cancelled: "Client request cancelled",
  write_failed: "Client stream write failed", flush_failed: "Client stream flush failed",
};
const streamFrameKinds = { data: "Data frame", done: "Completion marker", other: "Comment or other frame" };
const sourceNames = { detector_observation: "Detector observation", gateway_observation: "Gateway observation", caller_declared: "Caller-declared link", gateway_capture: "Gateway capture", gateway_snapshot: "Gateway policy snapshot" };
const statusMessages = {
  idle: "Select an application to load retained evidence.", loading: "Loading retained evidence metadata…",
  ready: "Retained evidence metadata loaded. Content remains hidden until requested.", empty: "No retained evidence matched this application and filter.",
  error: "Evidence could not be loaded. No safety conclusion can be drawn.", missing: "This evidence is unavailable or expired. Its content cannot be reconstructed.",
};

export function createEvidenceConsole({ request, getState }) {
  let epoch = 0, configEpoch = 0, revealEpoch = 0;
  let config = null, items = [], detail = null, graph = null, requestFilter = "";
  let listState = "idle", graphState = "idle", configState = "idle", busy = false;
  let revealedObject = "", revealedView = "", redactionState = "", contentMessage = "", revealing = false;
  let taskEpoch = 0, taskView = null, taskState = "idle";
  let snapshotEpoch = 0, taskArchive = null, taskArchives = [], snapshotState = "idle";

  const applicationID = () => el("evidence-app").value;
  const scoped = suffix => `${suffix}${suffix.includes("?") ? "&" : "?"}application_id=${encodeURIComponent(applicationID())}`;
  const send = (path, value, method = "POST") => request(path, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(value) });

  function clearContent() {
    revealEpoch++; revealedObject = revealedView = redactionState = contentMessage = ""; revealing = false;
    el("evidence-content-text").textContent = "";
    el("evidence-content-status").textContent = "";
    el("evidence-content-label").textContent = "";
    el("evidence-content").hidden = true;
    el("evidence-content").dataset.state = "hidden";
    el("evidence-content").setAttribute("aria-busy", "false");
    contentControls();
  }

  function contentControls() {
    el("evidence-objects").querySelectorAll("[data-evidence-reveal]").forEach(button => {
      const object = detail?.objects.find(value => value.id === button.dataset.objectId);
      button.disabled = revealing || object?.content_state !== "retained" || button.dataset.evidenceReveal === "raw" && revealedObject !== object.id;
    });
  }

  function renderContentLabels() {
    el("evidence-content-label").textContent = revealedView ? t(revealedView === "raw" ? "Raw content" : "Redacted content") : "";
    el("evidence-content-status").textContent = contentMessage ? t(contentMessage, { state: redactionState || "—" }) : "";
  }

  function clearDetail() {
    clearContent(); detail = graph = null; graphState = "idle";
    el("evidence-detail").hidden = true;
    for (const id of ["evidence-detail-fields", "evidence-objects", "evidence-findings", "evidence-policies", "evidence-graph-nodes", "evidence-graph-edges"]) el(id).replaceChildren();
    el("evidence-graph-status").textContent = "";
    el("evidence-reveal-reason").value = "incident_review";
  }

  function clear() {
    epoch++; configEpoch++; busy = false;
    clearTask(); el("evidence-task-form").reset(); renderTaskScope([]);
    clearDetail(); items = []; listState = "idle"; requestFilter = "";
    el("evidence-app").value = "";
    renderList();
  }

  function renderApplications() {
    const apps = getState().applications, select = el("evidence-app"), previous = select.value;
    select.replaceChildren(new Option(t("Select an application"), ""));
    for (const app of apps) select.add(new Option(app.name, app.id));
    select.value = apps.some(app => app.id === previous) ? previous : "";
    if (previous && !select.value) clear();
    const chosen = [...el("evidence-app-options").querySelectorAll("input:checked")].map(input => input.value);
    renderScope(chosen);
    renderTaskScope(); renderTask();
    renderList();
  }

  function taskApplications() {
    return [...el("evidence-task-app-options").querySelectorAll("input:checked")].map(input => input.value).sort();
  }

  function clearTask() {
    taskEpoch++; taskView = null; taskState = "idle";
    snapshotEpoch++; taskArchive = null; taskArchives = []; snapshotState = "idle";
    renderTask();
  }

  function renderTaskScope(chosen = taskApplications()) {
    const list = el("evidence-task-app-options"); list.replaceChildren();
    const apps = getState().applications;
    if (chosen.some(id => !apps.some(app => app.id === id))) { clearTask(); clearContent(); }
    for (const app of apps) {
      const label = node("label", undefined, "check-line"), input = node("input"), description = node("span", app.name);
      input.type = "checkbox"; input.value = app.id; input.checked = chosen.includes(app.id);
      description.append(node("small", app.id)); label.append(input, description); list.append(label);
    }
  }

  async function openTaskCapture(row) {
    if (row.evidence_state !== "retained" || !taskView?.application_ids.includes(row.application_id)) return;
    const taskGeneration = taskEpoch;
    clearContent(); el("evidence-app").value = row.application_id; requestFilter = row.request_id;
    const loading = loadList(), generation = epoch;
    await loading;
    if (epoch === generation && taskEpoch === taskGeneration && applicationID() === row.application_id) {
      await loadDetail(row.evidence_id);
      if (detail?.id === row.evidence_id) el("evidence-detail").scrollIntoView({ block: "start", behavior: "instant" });
    }
  }

  function renderTask() {
    const status = el("evidence-task-status"), rows = el("evidence-task-calls"), edges = el("evidence-task-edges");
    status.dataset.state = taskState;
    const messages = {
      idle: "Enter a trace ID and select applications to inspect.", loading: "Loading task evidence…",
      invalid: "Use a nonzero 32-character lowercase hexadecimal trace ID and select 1–16 applications.",
      error: "Task evidence could not be loaded. No safety conclusion can be drawn.",
      ready: "Loaded {calls} calls and {retained} readable captures. Missing evidence is unknown.",
      empty: "No calls were found in these observation windows and applications. This is not a safety determination.",
      archived: "Historical snapshot: {calls} calls and {retained} captures readable at save time.",
    };
    status.textContent = t(messages[taskState], { calls: taskView?.summary.calls ?? 0, retained: taskView?.summary.retained ?? 0 });
    el("evidence-task-load").disabled = taskState === "loading" || snapshotState === "saving";
    renderTaskSnapshots();
    el("evidence-task-results").hidden = !taskView;
    rows.replaceChildren(); edges.replaceChildren(); el("evidence-task-coverage").textContent = "";
    if (!taskView) return;
    const coverage = el("evidence-task-coverage");
    coverage.textContent = taskArchive ? t("These are saved observations. Evidence availability and application names may have changed; reload live task evidence for current observations.") : t("This live view uses up to {calls} calls and {captures} capture reads across the selected applications. It is not an archived or complete task record.", { calls: taskView.call_limit, captures: taskView.evidence_limit });
    if (taskView.result_truncated || taskView.audit_window_saturated) coverage.append(node("span", " " + t("Older or additional calls may be outside the observation limits.")));
    if (!taskView.audit_available) coverage.append(node("span", " " + t("Audit admission is unavailable; existing observations may still be visible.")));
    const states = { retained: "Retained capture available", not_found: "Capture not found; reason unknown", unavailable: "Capture could not be verified or read", not_loaded: "Capture outside this view's read budget" };
    const sources = { retained_evidence: "Retained evidence record", recent_audit: "Recent audit record", evidence_index: "Capture index only; call record unavailable" };
    for (const call of taskView.calls) {
      const row = node("tr"); row.dataset.taskRequest = call.request_id;
      const app = getState().applications.find(app => app.id === call.application_id);
      const identity = node("td"); identity.append(node("span", taskArchive ? call.application_id : app?.name || call.application_id), node("small", taskArchive ? "" : call.application_id), node("small", call.record?.trace?.agent_id || "—"));
      const request = node("td"); request.append(node("span", call.record ? formatDateTime(call.record.timestamp) : "—"), node("code", call.request_id));
      const operation = node("td"); operation.append(node("span", call.record?.operation || t("Unknown")), node("small", call.record?.outcome || t("Unknown")));
      const availability = node("td"); availability.append(node("span", t(states[call.evidence_state])), node("small", t(sources[call.record_source])));
      if (call.evidence_state === "retained" && !taskArchive) {
        const button = node("button", t("Open retained capture"), "text-button"); button.type = "button"; button.dataset.taskEvidence = call.evidence_id;
        button.addEventListener("click", () => openTaskCapture(call)); availability.append(button);
      }
      const findings = node("td", call.evidence_state === "retained" ? String(call.findings.length) : "—");
      for (const finding of call.findings) findings.append(node("small", `${finding.control} · ${finding.category} · ${finding.result}`));
      row.append(identity, request, operation, availability, findings); rows.append(row);
    }
    for (const edge of taskView.edges) {
      const item = node("li"); item.append(node("code", `${edge.source_request_id} → ${edge.target_request_id || edge.target_span_id}`),
        node("strong", edge.relation), node("small", `${t("Caller-declared link")} · ${edge.resolution}`)); edges.append(item);
    }
    if (!taskView.edges.length) edges.append(node("li", t("No declared relationships were observed in this view.")));
  }

  async function loadTask(event) {
    event.preventDefault(); clearContent();
    const trace = el("evidence-task-trace").value, ids = taskApplications();
    clearTask();
    if (!/^[0-9a-f]{32}$/.test(trace) || /^0+$/.test(trace) || ids.length < 1 || ids.length > 16) { taskState = "invalid"; renderTask(); return; }
    const generation = taskEpoch, query = new URLSearchParams({ limit: "128" });
    for (const id of ids) query.append("application_id", id);
    taskState = "loading"; renderTask();
    try {
      const value = await request(`/api/v1/evidence-traces/${trace}?${query}`);
      if (generation !== taskEpoch) return;
      validateTaskView(value, trace, ids);
      taskView = value; taskState = value.calls.length ? "ready" : "empty";
    } catch { if (generation === taskEpoch) taskState = "error"; }
    if (generation === taskEpoch) renderTask();
  }

  function validateTaskView(value, trace, ids) {
    const states = ["retained", "not_found", "unavailable", "not_loaded"];
    if (!value || !/^[0-9a-f]{64}$/.test(value.view_sha256) || value.trace_id !== trace || value.scope !== "selected_applications" || value.coverage !== "retained_evidence_and_recent_audit" ||
        !Array.isArray(value.application_ids) || JSON.stringify(value.application_ids.slice().sort()) !== JSON.stringify(ids) ||
        !Array.isArray(value.calls) || value.calls.length > 128 || !Array.isArray(value.edges) || !value.summary ||
        value.calls.some(call => !ids.includes(call.application_id) || !states.includes(call.evidence_state) || !Array.isArray(call.findings) ||
          (call.record && (call.record.application_id !== call.application_id || call.record.request_id !== call.request_id || call.record.trace?.trace_id !== trace)) ||
          (call.evidence_state === "retained" && !/^ev_[A-Za-z0-9_-]{22}$/.test(call.evidence_id)))) throw new Error("invalid_task_scope");
  }

  function taskArchiveQuery(ids) {
    const query = new URLSearchParams();
    for (const id of ids) query.append("application_id", id);
    return query;
  }

  function renderTaskSnapshots() {
    const loading = ["saving", "loading", "opening"].includes(snapshotState);
    el("evidence-task-save").disabled = !taskView || !!taskArchive || loading;
    el("evidence-task-archives-load").disabled = loading || taskState === "loading";
    const messages = {
      idle: "", saving: "Saving the unchanged task view…", loading: "Loading saved task snapshots…", opening: "Opening saved task snapshot…",
      ready: "Saved snapshots match this exact trace and application selection.", empty: "No saved snapshots match this exact scope.",
      saved: "Task snapshot saved. Content retention has not changed.", opened: "Saved task snapshot loaded and locally authenticated.",
      changed: "The task view changed. Reload task evidence before saving.",
      error: "Snapshot operation failed. Reload saved snapshots before retrying an uncertain save.",
    };
    const status = el("evidence-task-archive-status"); status.dataset.state = snapshotState; status.textContent = messages[snapshotState] ? t(messages[snapshotState]) : "";
    const list = el("evidence-task-archives"); list.replaceChildren();
    for (const summary of taskArchives) {
      const item = node("li"), button = node("button", `${formatDateTime(summary.created_at)} · ${summary.id}`, "text-button");
      button.type = "button"; button.dataset.taskSnapshot = summary.id; button.disabled = loading;
      button.addEventListener("click", () => openTaskSnapshot(summary.id)); item.append(button); list.append(item);
    }
    el("evidence-task-snapshot").hidden = !taskArchive;
    el("evidence-task-snapshot-meta").textContent = taskArchive ? t("Snapshot {id} · saved {time} · JSON SHA-256 {digest}", { id: taskArchive.summary.id, time: formatDateTime(taskArchive.snapshot.created_at), digest: taskArchive.summary.sha256 }) : "";
    for (const format of ["json", "markdown"]) {
      const link = el(`evidence-task-export-${format}`); link.removeAttribute("href");
      if (taskArchive) link.href = `/api/v1/evidence-traces/${taskArchive.snapshot.view.trace_id}/snapshots/${taskArchive.summary.id}/export/${format}?${taskArchiveQuery(taskArchive.snapshot.view.application_ids)}`;
    }
  }

  function showTaskSnapshot(value, trace, ids) {
    if (!value?.snapshot || !/^tsk_[A-Za-z0-9_-]{22}$/.test(value.summary?.id) || value.snapshot.id !== value.summary.id ||
        value.integrity !== "authenticated_local" || !/^[0-9a-f]{64}$/.test(value.summary.sha256)) throw new Error("invalid_snapshot");
    validateTaskView(value.snapshot.view, trace, ids);
    epoch++; busy = false; clearDetail(); renderList();
    taskArchive = value; taskView = value.snapshot.view; taskState = "archived";
  }

  async function saveTaskSnapshot() {
    if (!taskView || taskArchive || snapshotState === "saving") return;
    clearContent();
    const view = taskView, generation = taskEpoch, operation = ++snapshotEpoch;
    snapshotState = "saving"; renderTask();
    const query = taskArchiveQuery(view.application_ids); query.set("limit", String(view.call_limit));
    try {
      const value = await send(`/api/v1/evidence-traces/${view.trace_id}/snapshots?${query}`, { expected_view_sha256: view.view_sha256 });
      if (generation !== taskEpoch || operation !== snapshotEpoch) return;
      showTaskSnapshot(value, view.trace_id, view.application_ids); snapshotState = "saved";
    } catch (error) { if (generation === taskEpoch && operation === snapshotEpoch) snapshotState = error.code === "task_view_changed" ? "changed" : "error"; }
    if (generation === taskEpoch && operation === snapshotEpoch) renderTask();
  }

  async function loadTaskSnapshots() {
    const trace = el("evidence-task-trace").value, ids = taskApplications();
    if (!/^[0-9a-f]{32}$/.test(trace) || /^0+$/.test(trace) || ids.length < 1 || ids.length > 16) { taskState = "invalid"; renderTask(); return; }
    clearContent();
    const generation = taskEpoch, operation = ++snapshotEpoch;
    taskArchives = []; snapshotState = "loading"; renderTask();
    try {
      const value = await request(`/api/v1/evidence-traces/${trace}/snapshots?${taskArchiveQuery(ids)}`);
      if (generation !== taskEpoch || operation !== snapshotEpoch) return;
      if (!Array.isArray(value.items) || value.items.length > 256 || value.items.some(item => !/^tsk_[A-Za-z0-9_-]{22}$/.test(item.id) || item.trace_id !== trace || JSON.stringify(item.application_ids) !== JSON.stringify(ids))) throw new Error("invalid_snapshot_scope");
      taskArchives = value.items; snapshotState = taskArchives.length ? "ready" : "empty";
    } catch { if (generation === taskEpoch && operation === snapshotEpoch) snapshotState = "error"; }
    if (generation === taskEpoch && operation === snapshotEpoch) renderTask();
  }

  async function openTaskSnapshot(id) {
    clearContent();
    const trace = el("evidence-task-trace").value, ids = taskApplications(), generation = taskEpoch, operation = ++snapshotEpoch;
    taskView = taskArchive = null; taskState = "idle"; snapshotState = "opening"; renderTask();
    try {
      const value = await request(`/api/v1/evidence-traces/${trace}/snapshots/${id}?${taskArchiveQuery(ids)}`);
      if (generation !== taskEpoch || operation !== snapshotEpoch) return;
      if (value.summary?.id !== id) throw new Error("invalid_snapshot_id");
      showTaskSnapshot(value, trace, ids); snapshotState = "opened";
    } catch { if (generation === taskEpoch && operation === snapshotEpoch) snapshotState = "error"; }
    if (generation === taskEpoch && operation === snapshotEpoch) renderTask();
  }

  function renderScope(chosen) {
    const list = el("evidence-app-options"); list.replaceChildren();
    const apps = getState().applications;
    if (!apps.length) list.append(node("p", t("Create an application before enabling evidence capture."), "field-hint"));
    for (const app of apps) {
      const label = node("label", undefined, "check-line"), input = node("input"), description = node("span", app.name);
      input.type = "checkbox"; input.value = app.id; input.checked = chosen.includes(app.id);
      description.append(node("small", app.id)); label.append(input, description); list.append(label);
    }
  }

  function renderConfigStatus() {
    const messages = {
      idle: "Not loaded", loading: "Loading retention settings…", saving: "Saving retention settings…",
      ready: "Saved revision {revision}. Changes apply to new requests.", error: "Retention settings could not be loaded. Capture has not been changed.",
      invalid: "Select an application and valid retention limits before enabling capture.", conflict: "Retention settings changed elsewhere. Reload before saving.",
      failed: "Retention settings were not saved. Check the selected applications and limits.",
    };
    el("evidence-config-status").textContent = t(messages[configState], { revision: config?.revision ?? "—" });
    el("evidence-config-status").dataset.state = configState;
    el("evidence-config-fields").disabled = !config || ["loading", "saving"].includes(configState);
    el("evidence-reload-config").disabled = ["loading", "saving"].includes(configState);
  }

  async function loadConfig() {
    const generation = ++configEpoch;
    configState = "loading"; renderConfigStatus();
    try {
      const value = await request("/api/v1/evidence/config");
      if (generation !== configEpoch) return;
      if (value.schema_version !== 1 || !Object.hasOwn(captureModes, value.mode) || !Array.isArray(value.application_ids) || !Number.isSafeInteger(value.revision)) throw new Error("invalid_config");
      config = value; configState = "ready";
      el("evidence-mode").value = value.mode;
      el("evidence-retention").value = value.retention_days;
      el("evidence-max-bytes").value = value.max_content_bytes;
      renderScope(value.application_ids);
    } catch { if (generation === configEpoch) { config = null; configState = "error"; } }
    if (generation === configEpoch) renderConfigStatus();
  }

  async function saveConfig(event) {
    event.preventDefault();
    if (!config || ["loading", "saving"].includes(configState)) return;
    const mode = el("evidence-mode").value, ids = [...el("evidence-app-options").querySelectorAll("input:checked")].map(input => input.value);
    const days = Number(el("evidence-retention").value), bytes = Number(el("evidence-max-bytes").value);
    if (!Object.hasOwn(captureModes, mode) || mode !== "disabled" && !ids.length || !Number.isSafeInteger(days) || days < 1 || days > 365 || !Number.isSafeInteger(bytes) || bytes < 4096 || bytes > 1048576) {
      configState = "invalid"; renderConfigStatus(); return;
    }
    const generation = ++configEpoch;
    configState = "saving"; renderConfigStatus(); clearContent();
    try {
      const value = await send("/api/v1/evidence/config", { schema_version: 1, revision: config.revision, mode, application_ids: ids, retention_days: days, max_content_bytes: bytes }, "PUT");
      if (generation !== configEpoch) return;
      config = value; configState = "ready";
    } catch (error) { if (generation === configEpoch) configState = error.status === 409 ? "conflict" : "failed"; }
    if (generation === configEpoch) renderConfigStatus();
  }

  function renderList() {
    const list = el("evidence-list"); list.replaceChildren();
    const status = el("evidence-status"); status.dataset.state = listState; status.textContent = t(statusMessages[listState]);
    if (requestFilter) status.append(node("code", ` ${requestFilter}`));
    el("evidence-refresh").disabled = busy || !applicationID();
    el("evidence-clear-filter").hidden = !requestFilter;
    for (const item of items) {
      const row = node("tr"); row.dataset.evidenceId = item.id;
      const identity = node("td"), button = node("button", item.request_id, "request-open");
      button.type = "button"; button.dataset.evidenceOpen = item.id;
      button.setAttribute("aria-label", t("View evidence for request {id}", { id: item.request_id }));
      button.addEventListener("click", () => loadDetail(item.id));
      identity.append(node("span", formatDateTime(item.created_at)), button);
      const capture = node("td"); capture.append(node("span", t(captureModes[item.mode] || item.mode)), node("small", t(deliveryStates[item.delivery_state] || "Delivery unknown")));
      const count = node("td"); count.append(node("span", String(item.object_count)), node("small", `${item.retained_bytes} B`));
      row.append(identity, capture, count, node("td", formatDateTime(item.expires_at))); list.append(row);
    }
  }

  async function loadList() {
    const app = applicationID(), generation = ++epoch;
    clearDetail(); items = [];
    if (!app) { busy = false; listState = "idle"; renderList(); return; }
    busy = true; listState = "loading"; renderList();
    try {
      const value = await request(scoped(`/api/v1/evidence?limit=50${requestFilter ? `&request_id=${encodeURIComponent(requestFilter)}` : ""}`));
      if (generation !== epoch) return;
      if (!Array.isArray(value.items) || value.items.some(item => item.application_id !== app || typeof item.id !== "string")) throw new Error("invalid_scope");
      items = value.items; listState = items.length ? "ready" : "empty";
    } catch { if (generation === epoch) listState = "error"; }
    if (generation === epoch) { busy = false; renderList(); }
  }

  function field(container, label, value) {
    const row = node("div"); row.append(node("dt", label), node("dd", value === undefined || value === null ? "—" : String(value))); container.append(row);
  }

  function renderStream(info, stream) {
    const section = node("section", undefined, "evidence-stream");
    section.dataset.endState = stream.end_state;
    const summary = node("p", t(streamEndStates[stream.end_state] || "Unknown"), "evidence-stream-state");
    section.append(summary, node("p", t(stream.scope === "validated_frames" ? "Validated upstream frames only" : "Frames prepared for client write attempts"), "field-hint"));
    const facts = node("dl", undefined, "detail-fields");
    field(facts, t("Observed frame count"), stream.frame_count);
    field(facts, t("SSE completion marker observed"), t(stream.done_seen ? "Yes" : "No"));
    if (stream.scope === "write_attempted_frames") field(facts, t("Bytes reported written by gateway"), stream.written_bytes);
    section.append(facts);
    if (stream.end_state !== "completed") section.append(node("p", t("This stream did not complete. Retained content covers only the recorded frames."), "field-hint"));
    const timeline = node("details", undefined, "evidence-stream-timeline");
    timeline.append(node("summary", t("Frame timeline ({count} retained entries)", { count: stream.frames?.length || 0 })));
    timeline.append(node("p", t("Offsets refer to this object's frame bytes. Times are gateway observations after request start, not token generation times."), "field-hint"));
    if (stream.frames_truncated) timeline.append(node("p", t("Only the first 128 frame entries are retained. Totals and content limits are independent of this timeline."), "field-hint"));
    const entries = node("ol");
    for (const frame of (stream.frames || []).slice(0, 128)) {
      const item = node("li");
      item.append(node("span", t("Frame {sequence} · {kind}", { sequence: frame.sequence, kind: t(streamFrameKinds[frame.kind] || "Unknown") })),
        node("small", t("Offset {offset} B · {bytes} B · +{elapsed} ms", { offset: frame.offset, bytes: frame.bytes, elapsed: frame.elapsed_ms })));
      entries.append(item);
    }
    timeline.append(entries); section.append(timeline); info.append(section);
  }

  function renderDetail() {
    if (!detail) return;
    el("evidence-detail").hidden = false;
    el("evidence-use-trace").hidden = !detail.trace_id;
    const fields = el("evidence-detail-fields"); fields.replaceChildren();
    const values = [
      [t("Evidence ID"), detail.id], [t("Request ID"), detail.request_id], [t("Application identity"), detail.application_id],
      [t("Created at"), formatDateTime(detail.created_at)], [t("Expires at"), formatDateTime(detail.expires_at)],
      [t("Capture revision"), detail.capture_revision], [t("Capture mode"), t(captureModes[detail.mode] || detail.mode)],
      [t("Maximum content bytes per object"), detail.max_content_bytes],
      [t("Gateway delivery state"), t(deliveryStates[detail.delivery_state] || "Delivery unknown")],
      [t("Audit committed"), detail.audit_committed ? t("Yes") : t("No")], [t("Integrity"), detail.integrity === "authenticated" ? t("Authenticated vault record") : t("Unknown")],
      [t("Trace ID (client correlation)"), detail.trace_id || "—"], [t("Operation"), detail.operation],
      [t("Recorded outcome"), detail.record?.outcome], [t("HTTP status"), detail.record?.http_status],
    ];
    for (const [label, value] of values) field(fields, label, value);
    const objects = el("evidence-objects"); objects.replaceChildren();
    for (const object of detail.objects || []) {
      const row = node("article", undefined, "evidence-object"); row.dataset.objectId = object.id;
      const label = object.stream ? (object.kind === "upstream_output" ? "Validated upstream stream" : "Client stream write attempts") : objectKinds[object.kind] || object.kind;
      const info = node("div"); info.append(node("strong", t(label)), node("code", object.id),
        node("small", `${t(contentStates[object.content_state] || object.content_state)} · ${object.bytes} B · ${object.media_type}`));
      if (object.fingerprint) info.append(node("small", t("Content fingerprint: {value}", { value: object.fingerprint })));
      if (object.stream) renderStream(info, object.stream);
      const actions = node("div", undefined, "evidence-object-actions");
      for (const view of ["redacted", "raw"]) {
        const button = node("button", t(view === "redacted" ? "View redacted text" : "View raw text"), "text-button");
        button.type = "button"; button.dataset.evidenceReveal = view; button.dataset.objectId = object.id;
        if (view === "raw") button.dataset.evidenceRaw = "";
        button.disabled = object.content_state !== "retained" || view === "raw" && revealedObject !== object.id;
        button.addEventListener("click", () => reveal(object.id, view)); actions.append(button);
      }
      row.append(info, actions); objects.append(row);
    }
    const findings = el("evidence-findings"); findings.replaceChildren();
    if (!detail.findings?.length) {
      const row = node("tr"), cell = node("td", t("No findings were recorded. This is not a safety determination."), "table-empty"); cell.colSpan = 4; row.append(cell); findings.append(row);
    }
    for (const finding of detail.findings || []) {
      const row = node("tr"); row.dataset.findingId = finding.id;
      const control = node("td"); control.append(node("span", finding.control), node("small", finding.category));
      const result = node("td"); result.append(node("span", finding.result), node("small", finding.reason));
      const source = node("td"); source.append(node("span", t(sourceNames[finding.source] || finding.source)), node("small", `${finding.detector_version || "—"} / ${finding.policy_revision ?? "—"}`));
      row.append(control, result, source, node("td", finding.object_id || "—")); findings.append(row);
    }
    const policies = el("evidence-policies"); policies.replaceChildren();
    if (!detail.policies?.length) policies.append(node("p", t("No policy snapshot was retained."), "field-hint"));
    for (const policy of detail.policies || []) {
      const section = node("section"); section.append(node("h4", `${policy.kind} · ${policy.id} / ${policy.revision}`), node("pre", JSON.stringify(policy.snapshot, null, 2))); policies.append(section);
    }
    renderGraph();
    contentControls();
  }

  function renderGraph() {
    const statuses = { idle: "", loading: "Loading evidence relationships…", ready: "Retained relationships loaded; graph completeness is not guaranteed.", error: "Relationships could not be loaded. Evidence details remain available." };
    el("evidence-graph-status").textContent = t(statuses[graphState]);
    if (graph?.result_truncated || graph?.unavailable_records) el("evidence-graph-status").append(node("span", " " + t("Some related evidence is unavailable or outside the graph limit.")));
    const nodes = el("evidence-graph-nodes"), edges = el("evidence-graph-edges"); nodes.replaceChildren(); edges.replaceChildren();
    if (!graph) return;
    for (const item of graph.nodes || []) {
      const row = node("li"); row.append(node("strong", item.label), node("small", item.type), node("code", item.id));
      if (item.evidence_id && item.evidence_id !== detail.id) {
        const button = node("button", t("Open related evidence"), "text-button"); button.type = "button";
        button.addEventListener("click", () => loadDetail(item.evidence_id)); row.append(button);
      }
      nodes.append(row);
    }
    for (const edge of graph.edges || []) {
      const row = node("li"); row.append(node("code", `${edge.source} → ${edge.target}`), node("strong", edge.relation),
        node("small", `${t(sourceNames[edge.provenance] || edge.provenance || "Unknown")} · ${edge.resolution || "—"}`)); edges.append(row);
    }
  }

  async function loadDetail(id) {
    const app = applicationID(), generation = ++epoch;
    if (!app) return;
    clearDetail(); busy = true; listState = "loading"; renderList();
    try {
      const value = await request(scoped(`/api/v1/evidence/${encodeURIComponent(id)}`));
      if (generation !== epoch) return;
      if (value.id !== id || value.application_id !== app || !Array.isArray(value.objects)) throw new Error("invalid_scope");
      detail = value; listState = "ready"; graphState = "loading"; renderDetail();
      try {
        const relationships = await request(scoped(`/api/v1/evidence/${encodeURIComponent(id)}/graph`));
        if (generation !== epoch) return;
        if (!Array.isArray(relationships.nodes) || !Array.isArray(relationships.edges) || relationships.scope !== "same_application" || relationships.application_id !== app || relationships.root_evidence_id !== id) throw new Error("invalid_graph");
        graph = relationships; graphState = "ready";
      } catch { if (generation === epoch) graphState = "error"; }
      if (generation === epoch) renderGraph();
    } catch (error) { if (generation === epoch) listState = [404, 410].includes(error.status) ? "missing" : "error"; }
    if (generation === epoch) { busy = false; renderList(); }
  }

  async function reveal(objectID, view) {
    if (revealing || !detail || !["redacted", "raw"].includes(view) || !detail.objects.some(object => object.id === objectID && object.content_state === "retained")) return;
    if (view === "raw" && revealedObject !== objectID) return;
    const id = detail.id, app = applicationID(), generation = epoch;
    const reason = el("evidence-reveal-reason").value;
    if (!["incident_review", "validation"].includes(reason)) return;
    clearContent(); const contentGeneration = revealEpoch; revealing = true; contentControls();
    el("evidence-content").hidden = false; el("evidence-content").dataset.state = "loading";
    el("evidence-content").setAttribute("aria-busy", "true");
    contentMessage = "Loading requested content…"; renderContentLabels();
    try {
      const value = await send(`/api/v1/evidence/${encodeURIComponent(id)}/reveal`, { application_id: app, object_id: objectID, view, reason });
      if (generation !== epoch || contentGeneration !== revealEpoch) return;
      if (value.evidence_id !== id || value.object_id !== objectID || value.view !== view || typeof value.text !== "string") throw new Error("invalid_reveal");
      revealedObject = objectID; revealedView = view; redactionState = value.redaction_state;
      contentMessage = "Access recorded. Redaction state: {state}. Treat retained content as untrusted data."; renderContentLabels();
      el("evidence-content-text").textContent = value.text;
      el("evidence-content").dataset.state = view;
    } catch (error) {
      if (generation !== epoch || contentGeneration !== revealEpoch) return;
      el("evidence-content-text").textContent = "";
      el("evidence-content").dataset.state = "error";
      contentMessage = [404, 410].includes(error.status) ? "This evidence is unavailable or expired. Its content cannot be reconstructed." : "Content could not be revealed. No content was retained in this view."; renderContentLabels();
    } finally {
      if (generation === epoch && contentGeneration === revealEpoch) { revealing = false; contentControls(); el("evidence-content").setAttribute("aria-busy", "false"); }
    }
  }

  el("evidence-app").addEventListener("change", () => { requestFilter = ""; loadList(); });
  el("evidence-task-form").addEventListener("submit", loadTask);
  el("evidence-task-save").addEventListener("click", saveTaskSnapshot);
  el("evidence-task-archives-load").addEventListener("click", loadTaskSnapshots);
  el("evidence-task-form").addEventListener("input", () => { clearTask(); epoch++; busy = false; clearDetail(); renderList(); });
  el("evidence-use-trace").addEventListener("click", () => {
    if (!detail?.trace_id) return;
    clearTask(); clearContent(); el("evidence-task-trace").value = detail.trace_id; renderTaskScope([applicationID()]);
    el("evidence-task-panel").open = true; el("evidence-task-trace").focus();
  });
  el("evidence-refresh").addEventListener("click", loadList);
  el("evidence-clear-filter").addEventListener("click", () => { requestFilter = ""; loadList(); });
  el("evidence-close-detail").addEventListener("click", () => { epoch++; busy = false; clearDetail(); listState = items.length ? "ready" : applicationID() ? "empty" : "idle"; renderList(); });
  el("evidence-hide-content").addEventListener("click", clearContent);
  el("evidence-reveal-reason").addEventListener("change", clearContent);
  el("evidence-config-form").addEventListener("submit", saveConfig);
  el("evidence-reload-config").addEventListener("click", loadConfig);
  window.addEventListener("pagehide", clear);
  document.addEventListener("visibilitychange", () => { if (document.hidden) clearContent(); });

  return {
    enter() { renderApplications(); loadConfig(); },
    clear,
    refresh: renderApplications,
    openRequest(app, id) { renderApplications(); el("evidence-app").value = app; requestFilter = id; loadList(); },
    relocalize() { renderApplications(); renderConfigStatus(); renderDetail(); renderContentLabels(); },
    reset() { clear(); config = null; configState = "idle"; el("evidence-app").value = ""; el("evidence-config-form").reset(); el("evidence-app-options").replaceChildren(); renderConfigStatus(); },
  };
}
