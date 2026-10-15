import { createGatewayConsole } from "/gateway.js";
// The bootstrap console has no runtime dependencies, remote assets or telemetry.
// The server manages a revocable HttpOnly session; passwords never enter browser storage.
const element = (id) => document.getElementById(id);
let sessionGeneration = 0;
let setupRequired = false;
let current = null;
let saving = false;
const gateway = createGatewayConsole({ request, notice, copy, getInstance: () => current });

function notice(message, error = false) {
  const target = document.querySelector("dialog[open] .editor-notice") || (current ? element("notice") : element("login-notice"));
  target.textContent = message;
  target.classList.toggle("error", error);
  target.hidden = false;
}

async function request(path, options = {}) {
  const generation = sessionGeneration;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(path, {
      ...options,
      signal: controller.signal,
      credentials: "same-origin",
      cache: "no-store",
      headers: {
        "X-GovWeave-Request": "console",
        ...options.headers,
      },
    });
    const data = await response.json();
    if (path !== "/healthz" && generation !== sessionGeneration) throw new Error("管理会话已结束，请重新登录。");
    if (!response.ok) {
      if (response.status === 401 && !path.startsWith("/api/v1/auth/")) resetSession();
      throw new Error(data.error?.message || `请求失败 (${response.status})`);
    }
    return data;
  } catch (error) {
    if (error.name === "AbortError") throw new Error("请求超时，请检查服务连接后重试。");
    if (error instanceof TypeError || error instanceof SyntaxError) throw new Error("无法连接 GovWeave，请检查服务地址和反向代理配置。");
    throw error;
  } finally { clearTimeout(timer); }
}

function isManaged(source) { return source === "file" || source === "environment"; }
const sourceLabel = { file: "部署文件管理 · 只读", environment: "环境变量管理 · 只读", console: "控制台配置", unconfigured: "待配置" };

function render(view) {
  current = view;
  document.body.dataset.authenticated = "true";
  element("login-panel").hidden = true;
  element("dashboard").hidden = false;
  element("logout").hidden = false;
  element("workspace-name").textContent = view.organization_name || "企业工作空间";
  element("organization").value = view.organization_name;
  element("public-url").value = view.public_url;
  element("organization").disabled = isManaged(view.sources.organization_name);
  element("public-url").disabled = isManaged(view.sources.public_url);
  element("use-current").hidden = isManaged(view.sources.public_url);
  element("organization-source").textContent = sourceLabel[view.sources.organization_name];
  element("url-source").textContent = sourceLabel[view.sources.public_url];
  element("listen-addr").textContent = view.listen_addr;
  element("setup-title").textContent = view.configured ? "实例地址已配置" : "完成实例初始化";
  element("setup-description").textContent = view.configured ? "查看当前接入地址，或在下方调整实例配置。" : "设置组织名称和应用实际使用的网关访问地址。";
  element("setup-status").textContent = view.configured ? "配置就绪" : "待配置";
  element("save-settings").disabled = isManaged(view.sources.organization_name) && isManaged(view.sources.public_url);
  element("save-meta").textContent = view.updated_at ? `保存版本 ${view.revision} · ${new Date(view.updated_at).toLocaleString("zh-CN")}` : (view.configured ? "当前配置由部署参数提供" : "尚未保存配置");
  for (const [name, endpoint] of Object.entries(view.endpoints)) {
    element(`${name}-url`).textContent = endpoint.url || "保存配置后显示";
    document.querySelector(`[data-copy="${name}-url"]`).disabled = !endpoint.url;
  }
  gateway.renderExample();
  element("export-config").disabled = !view.configured;
}

function resetSession() {
  sessionGeneration++;
  current = null;
  document.body.dataset.authenticated = "false";
  gateway.reset();
  element("login-form").reset();
  element("settings-form").reset();
  element("dashboard").hidden = true;
  element("login-panel").hidden = false;
  element("logout").hidden = true;
  element("workspace-name").textContent = "企业工作空间";
  element("notice").hidden = true;
  element("login-notice").hidden = true;
}

function renderLogin(status) {
  setupRequired = status.setup_required;
  const allowed = !setupRequired || status.setup_allowed !== false;
  element("login-index").textContent = setupRequired ? "SETUP / 01" : "ACCESS / 01";
  element("login-title").textContent = setupRequired ? "设置管理员密码" : "欢迎回来";
  element("login-description").textContent = setupRequired ? "首次使用，设置一个密码即可进入控制台。" : "输入密码，继续管理你的 AI 网关。";
  element("login-submit-label").textContent = setupRequired ? "设置密码并进入" : "进入工作空间";
  element("admin-password").autocomplete = setupRequired ? "new-password" : "current-password";
  element("admin-password").placeholder = setupRequired ? "设置管理员密码" : "输入管理员密码";
  element("admin-password").disabled = !allowed;
  element("confirm-password-field").hidden = !setupRequired;
  element("confirm-password").required = setupRequired;
  element("confirm-password").disabled = !setupRequired || !allowed;
  element("login-submit").disabled = !allowed;
  if (!allowed) notice("旧版实例需要在部署主机上打开 localhost 地址设置密码。容器部署请参阅部署文档中的迁移步骤。", true);
}

async function enterWorkspace() {
  render(await request("/api/v1/instance"));
  gateway.enter();
  element("login-form").reset();
  element("login-notice").hidden = true;
  element("notice").hidden = true;
  await gateway.refresh();
}

async function restoreSession() {
  const status = await request("/api/v1/auth/status");
  renderLogin(status);
  if (status.authenticated) await enterWorkspace();
}

element("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (setupRequired && element("admin-password").value !== element("confirm-password").value) {
    notice("两次输入的密码不一致。", true);
    element("confirm-password").focus();
    return;
  }
  element("login-submit").disabled = true;
  try {
    await request(`/api/v1/auth/${setupRequired ? "setup" : "login"}`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: element("admin-password").value }),
    });
    renderLogin({ setup_required: false });
    await enterWorkspace();
  } catch (error) {
    element("login-form").reset();
    try { renderLogin(await request("/api/v1/auth/status")); } catch { /* Preserve the original failure. */ }
    notice(error.message, true);
  } finally { element("login-submit").disabled = element("admin-password").disabled; }
});

element("logout").addEventListener("click", async () => {
  element("logout").disabled = true;
  try {
    await request("/api/v1/auth/logout", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    resetSession();
    renderLogin({ setup_required: false });
  } catch (error) { notice(error.message, true); }
  finally { element("logout").disabled = false; }
});
element("use-current").addEventListener("click", () => { element("public-url").value = location.origin; });
element("reload-settings").addEventListener("click", async () => {
  if (saving) return;
  try { render(await request("/api/v1/instance")); notice("已加载当前生效的配置。"); }
  catch (error) { notice(error.message, true); }
});

element("settings-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (saving || !current) return;
  saving = true;
  element("save-settings").disabled = true;
  element("reload-settings").disabled = true;
  try {
    const view = await request("/api/v1/instance", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ schema_version: 1, revision: current.revision, organization_name: element("organization").value, public_url: element("public-url").value }),
    });
    render(view);
    notice("配置已保存。接入地址已更新；域名解析与网络连通性仍由企业部署环境决定。");
  } catch (error) { notice(error.message, true); }
  finally {
    saving = false;
    element("reload-settings").disabled = false;
    element("save-settings").disabled = current ? isManaged(current.sources.organization_name) && isManaged(current.sources.public_url) : false;
  }
});

async function copy(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(text);
    else {
      // Internal HTTP deployments may not expose the Clipboard API.
      const temporary = document.createElement("textarea");
      temporary.value = text;
      temporary.setAttribute("readonly", "");
      document.body.append(temporary);
      temporary.select();
      let copied;
      try { copied = document.execCommand("copy"); } finally { temporary.remove(); }
      if (!copied) throw new Error("clipboard unavailable");
    }
    notice("已复制到剪贴板。");
  } catch { notice("浏览器不允许自动复制，请选中文本后手动复制。", true); }
}

document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", () => copy(element(button.dataset.copy).textContent));
});
element("copy-example").addEventListener("click", () => copy(element("sdk-example").textContent));

element("export-config").addEventListener("click", () => {
  if (!current?.configured) return;
  const exported = { schema_version: 1, listen_addr: current.listen_addr, organization_name: current.organization_name, public_url: current.public_url };
  const blob = new Blob([JSON.stringify(exported, null, 2) + "\n"], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "govweave.deployment.json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  notice("已导出生效配置，不包含密码或密钥。使用该文件启动后，组织名称和访问地址将由部署文件管理。");
});

async function checkHealth(announce = false) {
  element("health-check").disabled = true;
  try {
    const health = await request("/healthz");
    if (health.status !== "ok" || health.service !== "govweave") throw new Error("当前地址未返回有效的 GovWeave 健康状态。");
    element("service-status").textContent = "本地服务在线";
    element("service-status").dataset.state = "ok";
    if (announce) notice("当前控制台服务响应正常。此检查不验证配置域名的连通性，也不表示模型或 MCP 已可用。");
  } catch (error) { element("service-status").textContent = "服务连接失败"; element("service-status").dataset.state = "error"; notice(error.message, true); }
  finally { element("health-check").disabled = false; }
}
element("health-check").addEventListener("click", () => checkHealth(true));
checkHealth();
restoreSession().catch(error => notice(error.message, true));
