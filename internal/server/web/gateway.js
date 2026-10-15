const el = id => document.getElementById(id);
const node = (tag, text, className) => {
  const value = document.createElement(tag);
  if (text !== undefined) value.textContent = text;
  if (className) value.className = className;
  return value;
};

export function createGatewayConsole({ request, notice, copy, getInstance }) {
  let state = { connections: [], applications: [] };
  let editingConnection = null, editingApplication = null;
  let auditSnapshot = null;
  const pages = {
    overview: ["运行总览", "OVERVIEW / 01", "从应用到模型，查看网关当前的接入关系与调用状态。"],
    connections: ["模型连接", "MODEL CONNECTIONS / 02", "定义上游模型与企业服务别名，统一应用的模型接入。"],
    applications: ["应用与密钥", "APPLICATION ACCESS / 03", "为每个应用划定访问边界，让密钥与模型授权各归其位。"],
    requests: ["调用记录", "REQUEST LOG / 04", "查看授权决定与执行结果，沿着请求 ID 追踪每次调用。"],
    deployment: ["部署与接入", "INSTANCE SETTINGS / 05", "设置企业自己的网关地址，生成可直接使用的接入信息。"],
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
  function chooseTab(name) {
    if (!getInstance() || !pages[name]) return;
    const [title, eyebrow, description] = pages[name];
    el("current-page-title").textContent = title;
    el("page-title").textContent = title;
    el("page-eyebrow").textContent = eyebrow;
    el("page-description").textContent = description;
    document.title = `${title} · GovWeave`;
    el("notice").hidden = true;
    document.querySelectorAll(".console-page").forEach(page => { page.hidden = page.id !== `page-${name}`; });
    document.querySelectorAll(".tabs [data-tab]").forEach(button => {
      const active = button.dataset.tab === name;
      button.classList.toggle("nav-active", active);
      if (active) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current");
    });
    window.scrollTo({ top: 0, behavior: "instant" });
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
    el("connection-form-title").textContent = "添加模型连接";
    el("credential-hint").textContent = "本地模型可留空。已保存的凭证使用本地密钥加密。";
  }
  function editConnection(connection) {
    resetConnection(); editingConnection = connection;
    el("connection-form-title").textContent = `编辑：${connection.name}`;
    for (const [field, key] of Object.entries({ name: "name", url: "base_url", model: "model", alias: "alias", timeout: "timeout_seconds" })) el(`connection-${field}`).value = connection[key];
    el("connection-enabled").checked = connection.enabled;
    el("connection-http").checked = connection.allow_insecure_http;
    el("credential-hint").textContent = connection.has_credential ? "已有加密凭证。留空保留原凭证，填写则替换。" : "尚未配置上游凭证。";
    el("connection-editor").showModal();
    el("connection-name").focus();
  }
  function renderConnections() {
    const list = el("connection-list"); list.replaceChildren();
    const query = el("connection-search").value.trim().toLocaleLowerCase();
    const connections = state.connections.filter(c => `${c.name} ${c.alias} ${c.model} ${c.base_url}`.toLocaleLowerCase().includes(query));
    el("connection-count").textContent = query ? `${connections.length} / ${state.connections.length} 个连接` : `${state.connections.length} 个连接`;
    if (!connections.length) list.append(query
      ? emptyState("没有找到匹配的连接", "试试其他名称、别名或上游模型。")
      : emptyState("连接你的第一个模型", "添加上游地址和模型别名，再为企业应用开放访问。", "添加模型连接 →", openConnection));
    for (const [index, connection] of connections.entries()) {
      const row = node("article", undefined, "list-item connection-columns"); row.dataset.connectionId = connection.id;
      const upstream = node("div", undefined, "item-upstream"), address = node("p", connection.base_url);
      address.title = connection.base_url;
      upstream.append(node("strong", connection.model), address);
      const status = node("div", undefined, "item-status");
      status.append(node("span", connection.enabled ? "已启用" : "已停用", `capability ${connection.enabled ? "available" : "planned"}`), node("small", `${connection.timeout_seconds}s · ${connection.has_credential ? "已配凭证" : "无凭证"}`));
      const actions = node("div", undefined, "item-actions");
      actions.append(action("编辑", async () => editConnection(connection)), action("检查连接", async () => {
        const result = await send(`/api/v1/connections/${connection.id}/test`, {});
        notice(`${connection.name}：${result.message}（${result.duration_ms} ms）`, !result.ok || !result.model_found);
      }));
      row.append(identity(connection.name, connection.alias, index), upstream, status, actions); list.append(row);
    }
  }
  function renderGrants(selected = []) {
    const container = el("application-grants"); container.replaceChildren();
    if (!state.connections.length) container.append(node("p", "请先添加模型连接。", "empty-state"));
    for (const connection of state.connections) {
      const label = node("label", undefined, "check-line grant-option");
      const input = node("input"); input.type = "checkbox"; input.value = connection.id; input.checked = selected.includes(connection.id);
      const description = node("span", connection.name + (connection.enabled ? "" : "（已停用）"));
      description.append(node("small", connection.alias));
      label.append(input, description); container.append(label);
    }
  }
  function resetApplication() {
    editingApplication = null; el("application-form").reset(); renderGrants();
    el("application-editor").querySelector(".editor-notice").hidden = true;
    el("application-form-title").textContent = "创建应用";
    el("save-application").textContent = "创建应用并生成密钥";
  }
  function showKey(key) {
    el("new-api-key").textContent = key || "";
    el("new-key-panel").hidden = !key;
  }
  function renderApplications() {
    const list = el("application-list"); list.replaceChildren();
    const query = el("application-search").value.trim().toLocaleLowerCase();
    const apps = state.applications.filter(a => `${a.name} ${a.key_prefix}`.toLocaleLowerCase().includes(query));
    el("application-count").textContent = query ? `${apps.length} / ${state.applications.length} 个应用` : `${state.applications.length} 个应用`;
    if (!apps.length) list.append(query
      ? emptyState("没有找到匹配的应用", "试试其他应用名称或密钥前缀。")
      : emptyState("为第一个应用划定访问边界", "选择允许使用的模型，为应用生成独立密钥。", "创建应用 →", openApplication));
    for (const [index, app] of apps.entries()) {
      const row = node("article", undefined, "list-item application-columns"); row.dataset.applicationId = app.id;
      const grants = node("div", undefined, "granted-models");
      for (const connection of state.connections.filter(c => app.allowed_connections.includes(c.id))) grants.append(node("span", connection.alias, "model-tag"));
      const status = node("div", undefined, "item-status");
      status.append(node("span", app.revoked ? "已撤销" : "有效", `capability ${app.revoked ? "revoked" : "available"}`));
      row.append(identity(app.name, `${app.key_prefix}…`, index), grants, status);
      if (!app.revoked) {
        const actions = node("div", undefined, "item-actions");
        actions.append(action("编辑授权", async () => {
          editingApplication = app; el("application-name").value = app.name; renderGrants(app.allowed_connections);
          el("application-form-title").textContent = `编辑：${app.name}`;
          el("save-application").textContent = "保存应用授权"; el("application-editor").showModal(); el("application-name").focus();
        }), action("轮换密钥", async () => {
          if (!window.confirm(`为“${app.name}”生成新密钥？旧密钥将立即失效，已受理的请求继续执行。`)) return;
          const result = await send(`/api/v1/applications/${app.id}/rotate`, { revision: app.revision });
          showKey(result.api_key); resetApplication(); await refresh(); notice("密钥已轮换，请更新应用的环境变量。");
        }), action("撤销应用", async () => {
          if (!window.confirm(`撤销“${app.name}”的密钥？此应用将不能发起新调用，已受理的请求继续执行。`)) return;
          await send(`/api/v1/applications/${app.id}/revoke`, { revision: app.revision });
          showKey(""); resetApplication(); await refresh(); notice("应用已撤销。");
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
    el("instance-host").textContent = instance?.public_url ? new URL(instance.public_url).host : "尚未配置访问地址";
    el("overview-setup").hidden = !instance || instance.configured;
    const app = state.applications.find(a => a.id === el("example-app").value && !a.revoked);
    const connection = app && state.connections.find(c => c.enabled && app.allowed_connections.includes(c.id));
    const comment = "# GOVWEAVE_API_KEY 应使用应用密钥，不能使用管理员密码。";
    let example = comment + "\n# 请先保存实例地址，再选择具有已启用模型授权的应用。";
    if (instance?.public_url && connection) example = [
      "import os", "from openai import OpenAI", "", comment,
      "client = OpenAI(", `    base_url=${JSON.stringify(instance.endpoints.models.url)},`,
      '    api_key=os.environ["GOVWEAVE_API_KEY"],', "    max_retries=0,", `    timeout=${connection.timeout_seconds + 10}.0,`, ")", "",
      "stream = client.chat.completions.create(", `    model=${JSON.stringify(connection.alias)},`,
      '    messages=[{"role": "user", "content": "总结这份资料"}],', "    stream=True,", ")",
      "for chunk in stream:", "    if chunk.choices:", '        print(chunk.choices[0].delta.content or "", end="", flush=True)',
    ].join("\n");
    el("sdk-example").textContent = example; el("copy-example").disabled = !(instance?.public_url && connection);
  }
  async function refresh() {
    state = await request("/api/v1/gateway");
    const selected = [...el("application-grants").querySelectorAll("input:checked")].map(input => input.value);
    renderConnections(); renderApplications(); renderGrants(selected);
    populateSelect("example-app", "选择接入应用", state.applications.filter(a => !a.revoked));
    if (!el("example-app").value) el("example-app").value = state.applications.find(a => !a.revoked)?.id || "";
    populateSelect("requests-app", "全部应用与连接检查", state.applications); renderExample();
    renderOverview();
    await refreshOverview();
  }
  const outcomes = { completed: "已完成", blocked: "已拦截", failed: "失败", cancelled: "已取消", rejected: "已拒绝", in_progress: "执行中", incomplete: "结束状态未知" };
  const operationNames = { "chat.completions": "模型对话", "models.list": "模型列表", "connection.test": "连接检查" };
  const applicationName = record => state.applications.find(a => a.id === record.application_id)?.name || (record.operation === "connection.test" ? "管理员检查" : "未识别应用");
  const statusClass = record => ["failed", "blocked", "rejected"].includes(record.outcome) ? "failed" : record.outcome === "completed" ? "available" : "muted-status";
  function inspectRequest(record) {
    el("request-detail").querySelector(".editor-notice").hidden = true;
    el("detail-request-id").textContent = record.request_id;
    const status = node("div", undefined, "detail-outcome");
    status.append(node("strong", outcomes[record.outcome] || record.outcome), node("span", `HTTP ${record.http_status || "—"}`));
    el("request-detail-state").replaceChildren(status);
    const fields = el("request-detail-fields"); fields.replaceChildren();
    const values = [
      ["调用时间", new Date(record.started_at).toLocaleString("zh-CN")], ["调用应用", applicationName(record)],
      ["模型别名", record.model || "—"], ["操作", record.operation + (record.streaming ? " · SSE" : "")],
      ["访问授权", record.decision === "allow" ? "已授权" : record.decision === "deny" ? "拒绝授权" : "未评估"],
      ["上游请求", record.upstream_attempted ? `已尝试 · ${record.upstream_status || "未收到状态码"}` : "未请求上游"],
      ["总耗时", `${record.duration_ms} ms`], ["上游首字节", record.first_byte_ms === undefined ? "—" : `${record.first_byte_ms} ms`],
      ["配置版本", String(record.policy_revision)], ["错误码", record.error_code || "—"], ["连接 ID", record.connection_id || "—"],
    ];
    for (const [label, value] of values) { const row = node("div"); row.append(node("dt", label), node("dd", value)); fields.append(row); }
    el("request-detail").showModal();
  }
  function renderRequestTable(view) {
    el("audit-status").textContent = `${view.available ? "记录正常" : "记录不可用 · 新调用已停止"} · ${(view.bytes / 1048576).toFixed(2)} / 128 MiB`;
    const list = el("request-list"); list.replaceChildren();
    if (!view.records.length) {
      const tr = node("tr"), td = node("td", undefined, "table-empty"); td.colSpan = 5;
      td.append(node("strong", "尚无调用记录"), node("span", "使用应用密钥发起请求后，在这里查看授权决定与执行结果。")); tr.append(td); list.append(tr);
    }
    for (const record of view.records) {
      const tr = node("tr"); tr.dataset.requestId = record.request_id;
      const identity = node("td"), requestButton = action(record.request_id, async () => inspectRequest(record));
      requestButton.className = "request-open"; requestButton.setAttribute("aria-label", `查看调用 ${record.request_id}`);
      identity.append(node("span", new Date(record.started_at).toLocaleString("zh-CN")), requestButton);
      const model = node("td"); model.append(node("span", applicationName(record)), node("code", record.model || "—"));
      const operation = node("td"); operation.append(node("span", (operationNames[record.operation] || record.operation) + (record.streaming ? " · 流式" : "")), node("small", record.decision === "allow" ? "已授权" : record.decision === "deny" ? "拒绝授权" : "未评估"));
      const result = node("td"); result.append(node("span", `${outcomes[record.outcome] || record.outcome} · ${record.http_status || "—"}`, `capability ${statusClass(record)}`), node("small", record.error_code || (record.upstream_attempted ? `上游 ${record.upstream_status || "未响应"}` : "未请求上游")));
      const duration = node("td", `${record.duration_ms} ms`); duration.append(node("small", record.first_byte_ms === undefined ? "—" : `首字节 ${record.first_byte_ms} ms`));
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
    if (!items.length) { list.append(node("div", type === "app" ? "尚无有效应用" : "尚无启用的模型", "topology-empty")); return; }
    for (const item of items.slice(0, 3)) {
      const row = node("div", undefined, "topology-node"), description = node("div");
      description.append(node("strong", item.name), node("small", type === "app" ? `${item.allowed_connections.length} MODEL GRANTS` : item.alias));
      row.append(node("span", type === "app" ? "A" : "M", "node-initial"), description, node("span", undefined, "status-dot"));
      list.append(row);
    }
    if (items.length > 3) list.append(node("div", `+ ${items.length - 3} MORE`, "topology-more"));
  }
  function renderOverview() {
    const models = state.connections.filter(c => c.enabled), apps = state.applications.filter(a => !a.revoked);
    el("nav-model-count").textContent = state.connections.length;
    el("nav-app-count").textContent = apps.length;
    el("metric-models").textContent = String(models.length).padStart(2, "0");
    el("metric-apps").textContent = String(apps.length).padStart(2, "0");
    el("metric-models-note").textContent = `${state.connections.length} 个连接 · ${state.connections.length - models.length} 个已停用`;
    el("metric-apps-note").textContent = `${state.applications.length} 个应用 · ${state.applications.length - apps.length} 个已撤销`;
    el("topology-app-count").textContent = `${apps.length} ACTIVE`;
    el("topology-model-count").textContent = `${models.length} ENABLED`;
    topologyNodes("topology-apps", apps, "app"); topologyNodes("topology-models", models, "model");
    if (!auditSnapshot) return;
    const chats = auditSnapshot.records.filter(r => r.operation === "chat.completions");
    const issues = chats.filter(r => ["failed", "blocked", "rejected"].includes(r.outcome)).length;
    el("metric-requests").textContent = String(chats.length).padStart(2, "0");
    el("metric-issues").textContent = String(issues).padStart(2, "0");
    el("metric-issues").classList.toggle("has-issues", issues > 0);
    el("metric-issues-note").textContent = auditSnapshot.available ? `${chats.filter(r => r.outcome === "completed").length} 次完成 · ${chats.filter(r => r.outcome === "cancelled").length} 次取消` : "记录不可用 · 新调用已停止";
    const list = el("overview-records"); list.replaceChildren();
    if (!auditSnapshot.records.length) {
      const empty = node("div", undefined, "overview-empty"), text = node("div");
      text.append(node("strong", "等待第一次调用"), node("p", "配置模型并为应用授权后，每次调用的结果会显示在这里。"));
      empty.append(text, action("开始接入 →", async () => chooseTab(models.length ? "applications" : "connections"))); list.append(empty);
    }
    for (const record of auditSnapshot.records.slice(0, 5)) {
      const row = node("div", undefined, "recent-row"), description = node("div");
      const issue = ["failed", "blocked", "rejected"].includes(record.outcome);
      description.append(node("strong", applicationName(record)), node("small", `${new Date(record.started_at).toLocaleTimeString("zh-CN", { hour12: false })} / ${operationNames[record.operation] || record.operation}`));
      const inspect = action(`${outcomes[record.outcome] || record.outcome} ↗`, async () => inspectRequest(record));
      inspect.className = `text-button capability ${statusClass(record)}`;
      row.append(node("span", issue ? "!" : "↗", `activity-mark${issue ? " issue" : ""}`), description, node("code", record.model || "—", "recent-model"), inspect, node("span", `${record.duration_ms} ms`, "recent-duration"));
      list.append(row);
    }
  }
  async function refreshOverview() {
    try {
      auditSnapshot = await request("/api/v1/requests?limit=100");
      el("overview-updated").textContent = `${new Date().toLocaleTimeString("zh-CN", { hour12: false })} 更新`;
      renderOverview();
    } catch (error) {
      auditSnapshot = null;
      el("metric-requests").textContent = el("metric-issues").textContent = "—";
      el("overview-updated").textContent = "调用记录加载失败";
      el("metric-issues-note").textContent = "请刷新重试";
      el("overview-records").replaceChildren(node("div", "暂时无法读取调用记录，请刷新重试。", "overview-empty"));
      throw error;
    }
  }
  el("connection-form").addEventListener("submit", event => {
    event.preventDefault(); act(el("save-connection"), async () => {
      const input = { revision: editingConnection?.revision || 0, name: el("connection-name").value, base_url: el("connection-url").value, model: el("connection-model").value, alias: el("connection-alias").value, enabled: el("connection-enabled").checked, allow_insecure_http: el("connection-http").checked, timeout_seconds: Number(el("connection-timeout").value) };
      if (el("clear-credential").checked && el("connection-key").value) throw new Error("清除凭证时请保持 API Key 输入框为空。");
      if (el("clear-credential").checked || el("connection-key").value) input.api_key = el("connection-key").value;
      await send(editingConnection ? `/api/v1/connections/${editingConnection.id}` : "/api/v1/connections", input, editingConnection ? "PUT" : "POST");
      el("connection-editor").close(); resetConnection(); await refresh(); notice("模型连接已保存。可检查连接，再为应用授予权限。");
    });
  });
  el("application-form").addEventListener("submit", event => {
    event.preventDefault(); act(el("save-application"), async () => {
      const allowed = [...el("application-grants").querySelectorAll("input:checked")].map(input => input.value);
      if (!allowed.length) throw new Error("请至少选择一个模型连接。");
      const result = await send(editingApplication ? `/api/v1/applications/${editingApplication.id}` : "/api/v1/applications", { revision: editingApplication?.revision || 0, name: el("application-name").value, allowed_connections: allowed }, editingApplication ? "PUT" : "POST");
      el("application-editor").close();
      if (result.api_key) showKey(result.api_key);
      resetApplication(); await refresh(); notice("应用已保存。接入示例可在“部署与接入”页面查看。");
    });
  });
  el("new-connection").addEventListener("click", openConnection);
  el("new-application").addEventListener("click", openApplication);
  el("connection-editor").addEventListener("close", resetConnection);
  el("application-editor").addEventListener("close", resetApplication);
  el("connection-search").addEventListener("input", renderConnections);
  el("application-search").addEventListener("input", renderApplications);
  el("refresh-overview").addEventListener("click", () => act(el("refresh-overview"), refresh));
  el("refresh-gateway").addEventListener("click", () => act(el("refresh-gateway"), async () => { await refresh(); resetConnection(); resetApplication(); notice("已加载最新配置，请重新选择需要编辑的连接或应用。"); }));
  el("refresh-requests").addEventListener("click", () => act(el("refresh-requests"), loadRequests));
  el("requests-app").addEventListener("change", () => act(el("refresh-requests"), loadRequests));
  el("example-app").addEventListener("change", renderExample);
  el("copy-new-key").addEventListener("click", () => copy(el("new-api-key").textContent));
  el("dismiss-key").addEventListener("click", () => showKey(""));
  return { refresh, renderExample, enter() { chooseTab("overview"); }, reset() {
    state = { connections: [], applications: [] }; editingConnection = editingApplication = null; auditSnapshot = null;
    for (const id of ["connection-editor", "application-editor", "request-detail"]) { if (el(id).open) el(id).close(); }
    el("connection-search").value = el("application-search").value = "";
    showKey(""); resetConnection(); resetApplication(); renderConnections(); renderApplications();
    el("request-list").replaceChildren(); el("overview-records").replaceChildren();
    for (const id of ["metric-models", "metric-apps", "metric-requests", "metric-issues", "nav-model-count", "nav-app-count"]) el(id).textContent = "—";
    el("overview-updated").textContent = "尚未加载";
    el("topology-apps").replaceChildren(); el("topology-models").replaceChildren();
    el("request-detail-fields").replaceChildren(); el("request-detail-state").replaceChildren(); el("detail-request-id").textContent = "";
    populateSelect("example-app", "请先创建应用", []); populateSelect("requests-app", "全部应用与连接检查", []);
    el("sdk-example").textContent = ""; el("audit-status").textContent = "";
    document.title = "GovWeave · 企业 AI 网关";
  } };
}
