import { t, formatDateTime, initializeLocale, onLocaleChange } from "/i18n.js";
import { createGatewayConsole } from "/gateway.js";
// The bootstrap console has no runtime dependencies, remote assets or telemetry.
// The server manages a revocable HttpOnly session; passwords never enter browser storage.
const element = (id) => document.getElementById(id);
let sessionGeneration = 0;
let setupRequired = false;
let loginStatus = { setup_required: false };
let authBusy = false;
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
    if (path !== "/healthz" && generation !== sessionGeneration) throw new Error(t("Your session has ended. Please sign in again."));
    if (!response.ok) {
      if (response.status === 401 && !path.startsWith("/api/v1/auth/")) resetSession();
      const error = new Error(t(data.error?.message) || t("Request failed ({status})", { status: response.status }));
      error.status = response.status;
      error.code = data.error?.code;
      throw error;
    }
    return data;
  } catch (error) {
    if (error.name === "AbortError") throw new Error(t("The request timed out. Check the connection and try again."));
    if (error instanceof TypeError || error instanceof SyntaxError) throw new Error(t("Cannot connect to GovWeave. Check the service URL and reverse proxy settings."));
    throw error;
  } finally { clearTimeout(timer); }
}

function isManaged(source) { return source === "file" || source === "environment"; }
const sourceLabel = { file: "Deployment file · Read-only", environment: "Environment · Read-only", console: "Console", unconfigured: "Not configured" };

function render(view, preserveInputs = false) {
  current = view;
  document.body.dataset.authenticated = "true";
  element("login-panel").hidden = true;
  element("dashboard").hidden = false;
  element("logout").hidden = false;
  element("workspace-name").textContent = view.organization_name || t("Enterprise workspace");
  if (!preserveInputs) {
    element("organization").value = view.organization_name;
    element("public-url").value = view.public_url;
  }
  element("organization").disabled = isManaged(view.sources.organization_name);
  element("public-url").disabled = isManaged(view.sources.public_url);
  element("use-current").hidden = isManaged(view.sources.public_url);
  element("organization-source").textContent = t(sourceLabel[view.sources.organization_name]);
  element("url-source").textContent = t(sourceLabel[view.sources.public_url]);
  element("listen-addr").textContent = view.listen_addr;
  element("setup-title").textContent = view.configured ? t("Instance URL configured") : t("Set up your instance");
  element("setup-description").textContent = view.configured ? t("Review your endpoints or update the instance settings below.") : t("Set your organization name and the gateway URL your applications will use.");
  element("setup-status").textContent = view.configured ? t("Configured") : t("Not configured");
  element("save-settings").disabled = isManaged(view.sources.organization_name) && isManaged(view.sources.public_url);
  element("save-meta").textContent = view.updated_at ? t("Revision {revision} · {time}", { revision: view.revision, time: formatDateTime(view.updated_at) }) : (view.configured ? t("Configuration is managed by deployment settings") : t("No saved configuration"));
  for (const [name, endpoint] of Object.entries(view.endpoints)) {
    element(`${name}-url`).textContent = endpoint.url || t("Available after saving settings");
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
  element("workspace-name").textContent = t("Enterprise workspace");
  element("notice").hidden = true;
  element("login-notice").hidden = true;
}

function renderLogin(status) {
  loginStatus = status;
  setupRequired = status.setup_required;
  const allowed = !setupRequired || status.setup_allowed !== false;
  element("login-index").textContent = setupRequired ? "SETUP / 01" : "ACCESS / 01";
  element("login-title").textContent = setupRequired ? t("Set your administrator password") : t("Welcome back");
  element("login-description").textContent = setupRequired ? t("Set a password to start using your instance.") : t("Enter your password to manage your AI gateway.");
  element("login-submit-label").textContent = setupRequired ? t("Set password & continue") : t("Enter workspace");
  element("admin-password").autocomplete = setupRequired ? "new-password" : "current-password";
  element("admin-password").placeholder = setupRequired ? t("Set your administrator password") : t("Enter your password");
  element("admin-password").disabled = !allowed;
  element("confirm-password-field").hidden = !setupRequired;
  element("confirm-password").required = setupRequired;
  element("confirm-password").disabled = !setupRequired || !allowed;
  element("login-submit").disabled = !allowed || authBusy;
  if (!allowed) notice(t("For a legacy instance, set your password from localhost on the deployment host. For containers, follow the migration guide."), true);
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
    notice(t("The passwords do not match."), true);
    element("confirm-password").focus();
    return;
  }
  authBusy = true;
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
  } finally { authBusy = false; element("login-submit").disabled = element("admin-password").disabled; }
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
  try { render(await request("/api/v1/instance")); notice(t("The current configuration has been loaded.")); }
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
    notice(t("Settings saved and endpoints updated. DNS and network connectivity depend on your deployment environment."));
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
    notice(t("Copied to clipboard."));
  } catch { notice(t("Your browser blocked copying. Select the text and copy it manually."), true); }
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
  notice(t("Configuration exported without passwords or keys. Using this file makes the organization name and URL deployment-managed."));
});

async function checkHealth(announce = false) {
  element("health-check").disabled = true;
  try {
    const health = await request("/healthz");
    if (health.status !== "ok" || health.service !== "govweave") throw new Error(t("This URL did not return a valid GovWeave health response."));
    element("service-status").textContent = t("Local service online");
    element("service-status").dataset.state = "ok";
    if (announce) notice(t("The console is responding. This check does not verify the configured domain, model readiness or MCP availability."));
  } catch (error) { element("service-status").textContent = t("Service unavailable"); element("service-status").dataset.state = "error"; notice(error.message, true); }
  finally { element("health-check").disabled = false; }
}
element("health-check").addEventListener("click", () => checkHealth(true));
initializeLocale();
onLocaleChange(() => {
  // Translate labels without resetting forms, selections, keys or the current page.
  document.querySelectorAll(".notice").forEach(item => { item.hidden = true; });
  renderLogin(loginStatus);
  if (current) render(current, true);
  gateway.relocalize();
  const state = element("service-status").dataset.state;
  element("service-status").textContent = t(state === "ok" ? "Local service online" : state === "error" ? "Service unavailable" : "Connecting");
});
checkHealth();
restoreSession().catch(error => notice(error.message, true));
