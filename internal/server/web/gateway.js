import { t, formatDateTime, formatTime } from "/i18n.js";
import { createPolicyConsole, policyResults, policyRules, renderPolicySnapshot } from "/policies.js";
import { createIntegrationConsole } from "/integration.js";
import { createEvidenceConsole } from "/evidence.js";
const el = id => document.getElementById(id);
const node = (tag, text, className) => {
  const value = document.createElement(tag);
  if (text !== undefined) value.textContent = text;
  if (className) value.className = className;
  return value;
};

export function createGatewayConsole({ request, notice, copy, getInstance }) {
  const policies = createPolicyConsole({ request, notice });
  let state = { connections: [], applications: [] };
  let editingConnection = null, editingApplication = null;
  let auditSnapshot = null, requestSnapshot = null, inspectedRequest = null;
  let inspectedPolicy = null, inspectedPolicyStatus = "idle", policyInspectionEpoch = 0;
  let overviewUpdatedAt = null, overviewFailed = false, activePage = "overview";
  const integration = createIntegrationConsole({ getState: () => state, getInstance, request, openRecords: async (applicationID, record) => {
    chooseTab("requests"); el("requests-app").value = applicationID;
    await act(el("refresh-requests"), async () => { await loadRequests(); if (record) inspectRequest(record); });
  } });
  const evidence = createEvidenceConsole({ request, getState: () => state });
  const pages = {
    overview: ["Overview", "OVERVIEW / 01", "See how applications connect to models and review recent activity."],
    connections: ["Model connections", "MODEL CONNECTIONS / 02", "Configure upstream models and service aliases for consistent application access."],
    applications: ["Applications & keys", "APPLICATION ACCESS / 03", "Give each application its own key and explicit model grants."],
    policies: ["Runtime policies", "RUNTIME POLICIES / 04", "Control credential egress with local checks before model execution."],
    requests: ["Request logs", "REQUEST LOG / 05", "Review authorization and execution results for each request ID."],
    evidence: ["Risk evidence", "RISK EVIDENCE / 06", "Inspect retained request evidence, recorded findings and their relationships."],
    deployment: ["Deployment & access", "INSTANCE SETTINGS / 06", "Set your gateway URL and generate connection details for your applications."],
  };
  const send = (path, data, method = "POST") => request(path, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });
  async function act(button, operation) {
    button.disabled = true;
    try { await operation(); } catch (error) { notice(error.message, true); }
    finally { button.disabled = false; }
  }
  function action(text, operation) {
    const button = node("button", text, "text-button");
    button.type = "button";
    button.addEventListener("click", () => act(button, operation));
    return button;
  }
  function renderHeading(name) {
    const [title, eyebrow, description] = pages[name].map(key => t(key));
    el("current-page-title").textContent = title;
    el("page-title").textContent = title;
    el("page-eyebrow").textContent = eyebrow;
    el("page-description").textContent = description;
    document.title = `${title} · GovWeave`;
  }
  function chooseTab(name) {
    if (!getInstance() || !pages[name]) return;
    if (name !== activePage) { integration.clear(); evidence.clear(); }
    activePage = name;
    renderHeading(name);
    el("notice").hidden = true;
    document.querySelectorAll(".console-page").forEach(page => { page.hidden = page.id !== `page-${name}`; });
    document.querySelectorAll(".tabs [data-tab]").forEach(button => {
      const active = button.dataset.tab === name;
      button.classList.toggle("nav-active", active);
      if (active) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current");
    });
    window.scrollTo({ top: 0, behavior: "instant" });
    if (name === "evidence") evidence.enter();
  }
  document.querySelectorAll("[data-tab]").forEach(button => button.addEventListener("click", event => {
    event.preventDefault(); chooseTab(button.dataset.tab);
    if (!getInstance()) return;
    if (button.dataset.tab === "requests") act(el("refresh-requests"), loadRequests);
    if (button.dataset.tab === "overview") act(el("refresh-overview"), refresh);
  }));
  document.querySelectorAll("[data-close]").forEach(button => button.addEventListener("click", () => el(button.dataset.close).close()));
  function openConnection() { resetConnection(); el("connection-editor").showModal(); el("connection-name").focus(); }
  function openApplication() { resetApplication(); el("application-editor").showModal(); el("application-name").focus(); }
  function emptyState(title, message, cta, operation) {
    const empty = node("div", undefined, "empty-state");
    empty.append(node("div", "+", "empty-symbol"), node("h3", title), node("p", message));
    if (cta) empty.append(action(cta, operation));
    return empty;
  }
  function identity(name, subline, index) {
    const cell = node("div", undefined, "item-identity"), text = node("div");
    text.append(node("strong", name), node("code", subline));
    cell.append(node("span", String(index + 1).padStart(2, "0"), "item-symbol"), text);
    return cell;
  }
  function resetConnection() {
    editingConnection = null; el("connection-form").reset();
    el("connection-editor").querySelector(".editor-notice").hidden = true;
    el("connection-form-title").textContent = t("Add model connection");
    el("credential-hint").textContent = t("Leave empty for models that need no key. Saved credentials are encrypted with a local key.");
  }
  function editConnection(connection) {
    resetConnection(); editingConnection = connection;
    el("connection-form-title").textContent = t("Edit: {name}", { name: connection.name });
    for (const [field, key] of Object.entries({ name: "name", url: "base_url", model: "model", alias: "alias", timeout: "timeout_seconds" })) el(`connection-${field}`).value = connection[key];
    el("connection-enabled").checked = connection.enabled;
    el("connection-http").checked = connection.allow_insecure_http;
    el("credential-hint").textContent = connection.has_credential ? t("An encrypted credential is saved. Leave empty to keep it, or enter a replacement.") : t("No upstream credential configured.");
    el("connection-editor").showModal();
    el("connection-name").focus();
  }
  function renderConnections() {
    const list = el("connection-list"); list.replaceChildren();
    const query = el("connection-search").value.trim().toLocaleLowerCase();
    const connections = state.connections.filter(c => `${c.name} ${c.alias} ${c.model} ${c.base_url}`.toLocaleLowerCase().includes(query));
    el("connection-count").textContent = query ? t(state.connections.length === 1 ? "{count} / {total} connection" : "{count} / {total} connections", { count: connections.length, total: state.connections.length }) : t(state.connections.length === 1 ? "{count} connection" : "{count} connections", { count: state.connections.length });
    if (!connections.length) list.append(query
      ? emptyState(t("No matching connections"), t("Try another name, alias or upstream model."))
      : emptyState(t("Connect your first model"), t("Add a provider URL and model alias, then grant access to your applications."), t("Add model connection →"), openConnection));
    for (const [index, connection] of connections.entries()) {
      const row = node("article", undefined, "list-item connection-columns"); row.dataset.connectionId = connection.id;
      const upstream = node("div", undefined, "item-upstream"), address = node("p", connection.base_url);
      address.title = connection.base_url;
      upstream.append(node("strong", connection.model), address);
      const status = node("div", undefined, "item-status");
      status.append(node("span", connection.enabled ? t("Enabled") : t("Disabled"), `capability ${connection.enabled ? "available" : "planned"}`), node("small", `${connection.timeout_seconds}s · ${connection.has_credential ? t("Credential saved") : t("No credential")}`));
      const actions = node("div", undefined, "item-actions");
      actions.append(action(t("Edit"), async () => editConnection(connection)), action(t("Check connection"), async () => {
        const result = await send(`/api/v1/connections/${connection.id}/test`, {});
        notice(`${connection.name}: ${t(result.message)} (${result.duration_ms} ms)`, !result.ok || !result.model_found);
      }));
      row.append(identity(connection.name, connection.alias, index), upstream, status, actions); list.append(row);
    }
  }
  function renderGrants(selected = []) {
    const container = el("application-grants"); container.replaceChildren();
    if (!state.connections.length) container.append(node("p", t("Add a model connection first."), "empty-state"));
    for (const connection of state.connections) {
      const label = node("label", undefined, "check-line grant-option");
      const input = node("input"); input.type = "checkbox"; input.value = connection.id; input.checked = selected.includes(connection.id);
      const description = node("span", connection.name + (connection.enabled ? "" : t(" (disabled)")));
      description.append(node("small", connection.alias));
      label.append(input, description); container.append(label);
    }
  }
  function resetApplication() {
    editingApplication = null; el("application-form").reset(); renderGrants();
    el("application-editor").querySelector(".editor-notice").hidden = true;
    el("application-form-title").textContent = t("Create application");
    el("save-application").textContent = t("Create application & key");
  }
  function showKey(key) {
    el("new-api-key").textContent = key || "";
    el("new-key-panel").hidden = !key;
  }
  function renderApplications() {
    const list = el("application-list"); list.replaceChildren();
    const query = el("application-search").value.trim().toLocaleLowerCase();
    const apps = state.applications.filter(a => `${a.name} ${a.key_prefix}`.toLocaleLowerCase().includes(query));
    el("application-count").textContent = query ? t(state.applications.length === 1 ? "{count} / {total} application" : "{count} / {total} applications", { count: apps.length, total: state.applications.length }) : t(state.applications.length === 1 ? "{count} application" : "{count} applications", { count: state.applications.length });
    if (!apps.length) list.append(query
      ? emptyState(t("No matching applications"), t("Try another application name or key prefix."))
      : emptyState(t("Authorize your first application"), t("Choose allowed models and create a separate key for your application."), t("Create application →"), openApplication));
    for (const [index, app] of apps.entries()) {
      const row = node("article", undefined, "list-item application-columns"); row.dataset.applicationId = app.id;
      const grants = node("div", undefined, "granted-models");
      for (const connection of state.connections.filter(c => app.allowed_connections.includes(c.id))) grants.append(node("span", connection.alias, "model-tag"));
      const status = node("div", undefined, "item-status");
      status.append(node("span", app.revoked ? t("Revoked") : t("Active"), `capability ${app.revoked ? "revoked" : "available"}`));
      row.append(identity(app.name, `${app.key_prefix}…`, index), grants, status);
      if (!app.revoked) {
        const actions = node("div", undefined, "item-actions");
        actions.append(action(t("Edit grants"), async () => {
          editingApplication = app; el("application-name").value = app.name; renderGrants(app.allowed_connections);
          el("application-form-title").textContent = t("Edit: {name}", { name: app.name });
          el("save-application").textContent = t("Save application grants"); el("application-editor").showModal(); el("application-name").focus();
        }), action(t("Rotate key"), async () => {
          if (!window.confirm(t("Generate a new key for “{name}”? The old key will stop working immediately. Accepted requests will continue.", { name: app.name }))) return;
          const result = await send(`/api/v1/applications/${app.id}/rotate`, { revision: app.revision });
          showKey(result.api_key); resetApplication(); await refresh(); notice(t("Key rotated. Update the application's environment variables."));
        }), action(t("Revoke application"), async () => {
          if (!window.confirm(t("Revoke the key for “{name}”? This application will no longer be able to start requests. Accepted requests will continue.", { name: app.name }))) return;
          await send(`/api/v1/applications/${app.id}/revoke`, { revision: app.revision });
          showKey(""); resetApplication(); await refresh(); notice(t("Application revoked."));
        })); row.append(actions);
      }
      if (app.revoked) row.append(node("div", "—", "item-actions muted"));
      list.append(row);
    }
  }
  function populateSelect(id, first, apps) {
    const select = el(id), value = select.value;
    select.replaceChildren(new Option(first, ""));
    for (const app of apps) select.add(new Option(app.name, app.id));
    if (apps.some(a => a.id === value)) select.value = value;
  }
  function renderExample() {
    const instance = getInstance();
    el("instance-host").textContent = instance?.public_url ? new URL(instance.public_url).host : t("Instance URL not configured");
    el("overview-setup").hidden = !instance || instance.configured;
    integration.render();
  }
  async function refresh() {
    state = await request("/api/v1/gateway");
    const selected = [...el("application-grants").querySelectorAll("input:checked")].map(input => input.value);
    renderConnections(); renderApplications(); renderGrants(selected);
    populateSelect("example-app", t("Select an application"), state.applications.filter(a => !a.revoked));
    if (!el("example-app").value) el("example-app").value = state.applications.find(a => !a.revoked)?.id || "";
    populateSelect("requests-app", t("All applications and connection checks"), state.applications); renderExample();
    evidence.refresh();
    renderOverview();
    await policies.refresh(state);
    await refreshOverview();
  }
  const outcomes = { completed: "Completed", blocked: "Blocked", failed: "Failed", cancelled: "Cancelled", rejected: "Rejected", in_progress: "In progress", incomplete: "Outcome unknown" };
  const operationNames = { "chat.completions": "Chat completion", "models.list": "Model list", "connection.test": "Connection check" };
  const applicationName = record => state.applications.find(a => a.id === record.application_id)?.name || (record.operation === "connection.test" ? t("Administrator check") : t("Unknown application"));
  const statusClass = record => ["failed", "blocked", "rejected"].includes(record.outcome) ? "failed" : record.outcome === "completed" ? "available" : "muted-status";
  function renderRequestPolicy() {
    el("request-policy-snapshot").hidden = !inspectedRequest?.content_policy;
    el("load-request-policy").hidden = !!inspectedPolicy;
    el("load-request-policy").disabled = inspectedPolicyStatus === "loading";
    const messages = {
      loading: "Loading policy snapshot…",
      missing: "This revision was not retained. Configurations from before the history baseline cannot be reconstructed.",
      error: "Could not load this policy snapshot. Try again.",
    };
    el("request-policy-status").textContent = t(messages[inspectedPolicyStatus] || "");
    el("request-policy-fields").replaceChildren();
    if (inspectedPolicy) renderPolicySnapshot(el("request-policy-fields"), inspectedPolicy);
  }
  el("load-request-policy").addEventListener("click", async () => {
    if (!inspectedRequest?.content_policy || inspectedPolicyStatus === "loading") return;
    const generation = policyInspectionEpoch, revision = inspectedRequest.content_policy.revision;
    inspectedPolicyStatus = "loading"; renderRequestPolicy();
    try {
      const snapshot = await request(`/api/v1/policies/credential-egress/revisions/${revision}`);
      if (generation !== policyInspectionEpoch) return;
      inspectedPolicy = snapshot; inspectedPolicyStatus = "loaded";
    } catch (error) {
      if (generation !== policyInspectionEpoch) return;
      inspectedPolicyStatus = error.status === 404 ? "missing" : "error";
    }
    if (generation === policyInspectionEpoch) renderRequestPolicy();
  });
  function inspectRequest(record) {
    if (inspectedRequest?.request_id !== record.request_id) {
      policyInspectionEpoch++; inspectedPolicy = null; inspectedPolicyStatus = "idle";
    }
    inspectedRequest = record;
    el("request-detail").querySelector(".editor-notice").hidden = true;
    el("detail-request-id").textContent = record.request_id;
    const status = node("div", undefined, "detail-outcome");
    status.append(node("strong", t(outcomes[record.outcome] || record.outcome)), node("span", `HTTP ${record.http_status || "—"}`));
    el("request-detail-state").replaceChildren(status);
    const fields = el("request-detail-fields"); fields.replaceChildren();
    const values = [
      [t("Started at"), formatDateTime(record.started_at)], [t("Application"), applicationName(record)],
      [t("Model alias"), record.model || "—"], [t("Action"), record.operation + (record.streaming ? " · SSE" : "")],
      [t("Access authorization"), record.decision === "allow" ? t("Allowed") : record.decision === "deny" ? t("Denied") : t("Not evaluated")],
      [t("Upstream request"), record.upstream_attempted ? t("Attempted · {status}", { status: record.upstream_status || t("No status received") }) : t("No upstream request")],
      [t("Total duration"), `${record.duration_ms} ms`], [t("Upstream first byte"), record.first_byte_ms === undefined ? "—" : `${record.first_byte_ms} ms`],
      [t("Configuration revision"), String(record.policy_revision)], [t("Error code"), record.error_code || "—"], [t("Connection ID"), record.connection_id || "—"],
    ];
    if (record.content_policy) {
      const policy = record.content_policy;
      values.push(
        [t("Credential policy"), t(policyResults[policy.result] || policy.result)],
        [t("Policy revision"), `${policy.id} / ${policy.revision} / ${policy.ruleset_version}`],
        [t("Matched rules"), policy.matched_rules.map(rule => t(policyRules[rule] || rule)).join(", ") || t("None")],
        [t("Policy check duration"), `${policy.check_duration_us} µs`],
      );
    } else values.push([t("Credential policy"), t("Not evaluated")]);
    for (const [label, value] of values) { const row = node("div"); row.append(node("dt", label), node("dd", value)); fields.append(row); }
    renderRequestPolicy();
    if (!el("request-detail").open) el("request-detail").showModal();
  }
  function renderRequestTable(view) {
    requestSnapshot = view;
    el("audit-status").textContent = `${view.available ? t("Logging available") : t("Logging unavailable · New requests stopped")} · ${(view.bytes / 1048576).toFixed(2)} / 128 MiB`;
    const list = el("request-list"); list.replaceChildren();
    if (!view.records.length) {
      const tr = node("tr"), td = node("td", undefined, "table-empty"); td.colSpan = 5;
      td.append(node("strong", t("No request records yet")), node("span", t("Send a request with an application key to see its authorization and execution results here."))); tr.append(td); list.append(tr);
    }
    for (const record of view.records) {
      const tr = node("tr"); tr.dataset.requestId = record.request_id;
      const identity = node("td"), requestButton = action(record.request_id, async () => inspectRequest(record));
      requestButton.className = "request-open"; requestButton.setAttribute("aria-label", t("View request {id}", { id: record.request_id }));
      identity.append(node("span", formatDateTime(record.started_at)), requestButton);
      if (record.application_id) {
        const retained = action(t("Risk evidence"), async () => { chooseTab("evidence"); evidence.openRequest(record.application_id, record.request_id); });
        retained.dataset.evidenceFor = record.request_id; identity.append(retained);
      }
      const model = node("td"); model.append(node("span", applicationName(record)), node("code", record.model || "—"));
      const operation = node("td"); operation.append(node("span", (t(operationNames[record.operation] || record.operation)) + (record.streaming ? t(" · Streaming") : "")), node("small", record.decision === "allow" ? t("Allowed") : record.decision === "deny" ? t("Denied") : t("Not evaluated")));
      const result = node("td"); result.append(node("span", `${t(outcomes[record.outcome] || record.outcome)} · ${record.http_status || "—"}`, `capability ${statusClass(record)}`), node("small", record.error_code || (record.upstream_attempted ? t("Upstream {status}", { status: record.upstream_status || t("No response") }) : t("No upstream request"))));
      if (record.content_policy?.matched_rules.length) result.append(node("small", t(policyResults[record.content_policy.result]), "policy-match"));
      const duration = node("td", `${record.duration_ms} ms`); duration.append(node("small", record.first_byte_ms === undefined ? "—" : t("First byte {duration} ms", { duration: record.first_byte_ms })));
      tr.append(identity, model, operation, result, duration); list.append(tr);
    }
  }
  async function loadRequests() {
    const view = await request(`/api/v1/requests?limit=100&application_id=${encodeURIComponent(el("requests-app").value)}`);
    renderRequestTable(view);
    if (!el("requests-app").value) { auditSnapshot = view; renderOverview(); }
  }
  function topologyNodes(id, items, type) {
    const list = el(id); list.replaceChildren();
    if (!items.length) { list.append(node("div", type === "app" ? t("No active applications") : t("No enabled models"), "topology-empty")); return; }
    for (const item of items.slice(0, 3)) {
      const row = node("div", undefined, "topology-node"), description = node("div");
      description.append(node("strong", item.name), node("small", type === "app" ? t(item.allowed_connections.length === 1 ? "{count} MODEL GRANT" : "{count} MODEL GRANTS", { count: item.allowed_connections.length }) : item.alias));
      row.append(node("span", type === "app" ? "A" : "M", "node-initial"), description, node("span", undefined, "status-dot"));
      list.append(row);
    }
    if (items.length > 3) list.append(node("div", t("+ {count} MORE", { count: items.length - 3 }), "topology-more"));
  }
  function renderOverview() {
    const models = state.connections.filter(c => c.enabled), apps = state.applications.filter(a => !a.revoked);
    el("nav-model-count").textContent = state.connections.length;
    el("nav-app-count").textContent = apps.length;
    el("metric-models").textContent = String(models.length).padStart(2, "0");
    el("metric-apps").textContent = String(apps.length).padStart(2, "0");
    el("metric-models-note").textContent = t(state.connections.length === 1 ? "{total} connection · {disabled} disabled" : "{total} connections · {disabled} disabled", { total: state.connections.length, disabled: state.connections.length - models.length });
    el("metric-apps-note").textContent = t(state.applications.length === 1 ? "{total} application · {revoked} revoked" : "{total} applications · {revoked} revoked", { total: state.applications.length, revoked: state.applications.length - apps.length });
    el("topology-app-count").textContent = t("{count} ACTIVE", { count: apps.length });
    el("topology-model-count").textContent = t("{count} ENABLED", { count: models.length });
    topologyNodes("topology-apps", apps, "app"); topologyNodes("topology-models", models, "model");
    if (!auditSnapshot) return;
    const chats = auditSnapshot.records.filter(r => r.operation === "chat.completions");
    const issues = chats.filter(r => ["failed", "blocked", "rejected"].includes(r.outcome)).length;
    el("metric-requests").textContent = String(chats.length).padStart(2, "0");
    el("metric-issues").textContent = String(issues).padStart(2, "0");
    el("metric-issues").classList.toggle("has-issues", issues > 0);
    el("metric-issues-note").textContent = auditSnapshot.available ? t("{completed} completed · {cancelled} cancelled", { completed: chats.filter(r => r.outcome === "completed").length, cancelled: chats.filter(r => r.outcome === "cancelled").length }) : t("Logging unavailable · New requests stopped");
    const list = el("overview-records"); list.replaceChildren();
    if (!auditSnapshot.records.length) {
      const empty = node("div", undefined, "overview-empty"), text = node("div");
      text.append(node("strong", t("Waiting for the first request")), node("p", t("Connect a model and authorize an application to see request results here.")));
      empty.append(text, action(t("Get started →"), async () => chooseTab(models.length ? "applications" : "connections"))); list.append(empty);
    }
    for (const record of auditSnapshot.records.slice(0, 5)) {
      const row = node("div", undefined, "recent-row"), description = node("div");
      const issue = ["failed", "blocked", "rejected"].includes(record.outcome);
      description.append(node("strong", applicationName(record)), node("small", `${formatTime(record.started_at)} / ${t(operationNames[record.operation] || record.operation)}`));
      const inspect = action(`${t(outcomes[record.outcome] || record.outcome)} ↗`, async () => inspectRequest(record));
      inspect.className = `text-button capability ${statusClass(record)}`;
      row.append(node("span", issue ? "!" : "↗", `activity-mark${issue ? " issue" : ""}`), description, node("code", record.model || "—", "recent-model"), inspect, node("span", `${record.duration_ms} ms`, "recent-duration"));
      list.append(row);
    }
  }
  async function refreshOverview() {
    try {
      auditSnapshot = await request("/api/v1/requests?limit=100");
      overviewUpdatedAt = new Date(); overviewFailed = false;
      el("overview-updated").textContent = t("Updated {time}", { time: formatTime(overviewUpdatedAt) });
      renderOverview();
    } catch (error) {
      auditSnapshot = null; overviewFailed = true;
      renderOverviewFailure();
      throw error;
    }
  }
  function renderOverviewFailure() {
    el("metric-requests").textContent = el("metric-issues").textContent = "—";
    el("overview-updated").textContent = t("Could not load request records");
    el("metric-issues-note").textContent = t("Refresh to try again");
    el("overview-records").replaceChildren(node("div", t("Request records are temporarily unavailable. Refresh to try again."), "overview-empty"));
  }
  el("connection-form").addEventListener("submit", event => {
    event.preventDefault(); act(el("save-connection"), async () => {
      const input = { revision: editingConnection?.revision || 0, name: el("connection-name").value, base_url: el("connection-url").value, model: el("connection-model").value, alias: el("connection-alias").value, enabled: el("connection-enabled").checked, allow_insecure_http: el("connection-http").checked, timeout_seconds: Number(el("connection-timeout").value) };
      if (el("clear-credential").checked && el("connection-key").value) throw new Error(t("Leave the API key field empty when removing the saved credential."));
      if (el("clear-credential").checked || el("connection-key").value) input.api_key = el("connection-key").value;
      await send(editingConnection ? `/api/v1/connections/${editingConnection.id}` : "/api/v1/connections", input, editingConnection ? "PUT" : "POST");
      el("connection-editor").close(); resetConnection(); await refresh(); notice(t("Connection saved. Check connectivity, then grant access to applications."));
    });
  });
  el("application-form").addEventListener("submit", event => {
    event.preventDefault(); act(el("save-application"), async () => {
      const allowed = [...el("application-grants").querySelectorAll("input:checked")].map(input => input.value);
      if (!allowed.length) throw new Error(t("Select at least one model connection."));
      const result = await send(editingApplication ? `/api/v1/applications/${editingApplication.id}` : "/api/v1/applications", { revision: editingApplication?.revision || 0, name: el("application-name").value, allowed_connections: allowed }, editingApplication ? "PUT" : "POST");
      el("application-editor").close();
      if (result.api_key) showKey(result.api_key);
      resetApplication(); await refresh(); notice(t("Application saved. Find connection examples under Deployment & access."));
    });
  });
  el("new-connection").addEventListener("click", openConnection);
  el("new-application").addEventListener("click", openApplication);
  el("connection-editor").addEventListener("close", resetConnection);
  el("application-editor").addEventListener("close", resetApplication);
  el("connection-search").addEventListener("input", renderConnections);
  el("application-search").addEventListener("input", renderApplications);
  el("refresh-overview").addEventListener("click", () => act(el("refresh-overview"), refresh));
  el("refresh-gateway").addEventListener("click", () => act(el("refresh-gateway"), async () => { await refresh(); resetConnection(); resetApplication(); notice(t("Latest configuration loaded. Select a connection or application to edit.")); }));
  el("refresh-requests").addEventListener("click", () => act(el("refresh-requests"), loadRequests));
  el("requests-app").addEventListener("change", () => act(el("refresh-requests"), loadRequests));
  el("copy-new-key").addEventListener("click", () => copy(el("new-api-key").textContent));
  el("dismiss-key").addEventListener("click", () => showKey(""));
  function relocalize() {
    if (!getInstance()) { document.title = t("GovWeave · Enterprise AI Gateway"); return; }
    renderHeading(activePage);
    policies.relocalize();
    evidence.relocalize();
    renderConnections(); renderApplications();
    const selected = [...el("application-grants").querySelectorAll("input:checked")].map(input => input.value);
    renderGrants(selected);
    populateSelect("example-app", t("Select an application"), state.applications.filter(a => !a.revoked));
    populateSelect("requests-app", t("All applications and connection checks"), state.applications);
    renderExample(); renderOverview();
    if (overviewUpdatedAt) el("overview-updated").textContent = t("Updated {time}", { time: formatTime(overviewUpdatedAt) });
    if (overviewFailed) renderOverviewFailure();
    if (requestSnapshot) renderRequestTable(requestSnapshot);
    if (el("request-detail").open && inspectedRequest) inspectRequest(inspectedRequest);
    el("connection-form-title").textContent = editingConnection ? t("Edit: {name}", { name: editingConnection.name }) : t("Add model connection");
    el("credential-hint").textContent = editingConnection
      ? t(editingConnection.has_credential ? "An encrypted credential is saved. Leave empty to keep it, or enter a replacement." : "No upstream credential configured.")
      : t("Leave empty for models that need no key. Saved credentials are encrypted with a local key.");
    el("application-form-title").textContent = editingApplication ? t("Edit: {name}", { name: editingApplication.name }) : t("Create application");
    el("save-application").textContent = t(editingApplication ? "Save application grants" : "Create application & key");
  }
  return { refresh, renderExample, relocalize, enter() { chooseTab("overview"); }, reset() {
    integration.clear();
    evidence.reset();
    policyInspectionEpoch++; inspectedPolicy = null; inspectedPolicyStatus = "idle";
    policies.reset();
    state = { connections: [], applications: [] }; editingConnection = editingApplication = null; auditSnapshot = requestSnapshot = inspectedRequest = null;
    overviewUpdatedAt = null; overviewFailed = false;
    for (const id of ["connection-editor", "application-editor", "request-detail"]) { if (el(id).open) el(id).close(); }
    el("connection-search").value = el("application-search").value = "";
    showKey(""); resetConnection(); resetApplication(); renderConnections(); renderApplications();
    el("request-list").replaceChildren(); el("overview-records").replaceChildren();
    for (const id of ["metric-models", "metric-apps", "metric-requests", "metric-issues", "nav-model-count", "nav-app-count"]) el(id).textContent = "—";
    el("overview-updated").textContent = t("Not loaded");
    el("topology-apps").replaceChildren(); el("topology-models").replaceChildren();
    el("request-detail-fields").replaceChildren(); el("request-detail-state").replaceChildren(); el("detail-request-id").textContent = "";
    renderRequestPolicy();
    populateSelect("example-app", t("Create an application first"), []); populateSelect("requests-app", t("All applications and connection checks"), []);
    el("sdk-example").textContent = ""; el("audit-status").textContent = "";
    document.title = t("GovWeave · Enterprise AI Gateway");
  } };
}
