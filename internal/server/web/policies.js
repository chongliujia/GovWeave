import { t, formatDateTime } from "/i18n.js";
const el = id => document.getElementById(id);
export const policyResults = { disabled: "Disabled", not_applicable: "Outside scope", allow: "No matches", observe: "Observed match", block: "Blocked by policy", error: "Check failed" };
export const policyRules = { private_key: "Private key markers", api_key: "API key patterns" };
const modes = { disabled: "Disabled", observe: "Observe", block: "Block" };
const hints = {
  disabled: "No credential checks are performed. Application access controls remain active.",
  observe: "Record matching rule IDs and forward the original request, including any matched credentials.",
  block: "Reject matching requests with HTTP 403 before contacting the model provider.",
};
export function renderPolicySnapshot(target, snapshot) {
  target.replaceChildren();
  const values = [
    [t("Policy revision"), `${snapshot.id} / ${snapshot.revision} / ${snapshot.ruleset_version}`],
    [t("Policy mode"), t(modes[snapshot.mode])],
    [t("Detection rules"), snapshot.rules.map(rule => t(policyRules[rule] || rule)).join(", ")],
    [t("Applications"), snapshot.application_ids.length ? snapshot.application_ids.join(", ") : t("All applications, including future ones")],
    [t("Model connections"), snapshot.connection_ids.length ? snapshot.connection_ids.join(", ") : t("All model connections, including future ones")],
    [t("Saved at"), snapshot.updated_at ? formatDateTime(snapshot.updated_at) : t("Initial default")],
  ];
  for (const [label, value] of values) {
    const row = document.createElement("div"), term = document.createElement("dt"), detail = document.createElement("dd");
    term.textContent = label; detail.textContent = value; row.append(term, detail); target.append(row);
  }
}
export function createPolicyConsole({ request, notice }) {
  let saved = null, resources = { applications: [], connections: [] }, busy = false;
  const selected = kind => [...el(`policy-${kind}-options`).querySelectorAll("input:checked")].map(input => input.value);
  function options(kind, items, chosen) {
    const list = el(`policy-${kind}-options`); list.replaceChildren();
    list.hidden = el(`policy-${kind}-scope`).value === "all";
    if (!items.length) {
      const message = document.createElement("p"); message.className = "field-hint";
      message.textContent = t("Create an application or model connection before selecting a scope."); list.append(message);
    }
    for (const item of items) {
      const label = document.createElement("label"), input = document.createElement("input"), text = document.createElement("span");
      label.className = "check-line"; input.type = "checkbox"; input.value = item.id; input.checked = chosen.includes(item.id);
      text.textContent = item.name;
      if (item.alias) { const alias = document.createElement("small"); alias.textContent = item.alias; text.append(alias); }
      label.append(input, text); list.append(label);
    }
  }
  function render() {
    el("policy-mode-hint").textContent = t(hints[el("policy-mode").value]);
    el("policy-live-status").textContent = saved ? t("Saved mode: {mode}", { mode: t(modes[saved.mode]) }) : t("Not loaded");
    el("policy-live-status").className = `capability ${saved?.mode === "block" ? "available" : "planned"}`;
    el("policy-save-meta").textContent = saved ? (saved.updated_at ? t("Revision {revision} · {time}", { revision: saved.revision, time: formatDateTime(saved.updated_at) }) : t("Default policy · Disabled until configured")) : t("Not loaded");
    options("app", resources.applications, selected("app"));
    options("model", resources.connections, selected("model"));
  }
  function restore(snapshot) {
    saved = snapshot;
    el("policy-mode").value = saved.mode;
    for (const [id, rule] of [["policy-private-key", "private_key"], ["policy-api-key", "api_key"]]) el(id).checked = saved.rules.includes(rule);
    el("policy-app-scope").value = saved.application_ids.length ? "selected" : "all";
    el("policy-model-scope").value = saved.connection_ids.length ? "selected" : "all";
    options("app", resources.applications, saved.application_ids);
    options("model", resources.connections, saved.connection_ids);
    render();
  }
  async function run(operation) {
    if (busy) return;
    busy = true; el("policy-fields").disabled = true; el("retry-policy").disabled = true;
    try { await operation(); el("retry-policy").hidden = true; }
    catch (error) { notice(error.message, true); el("retry-policy").hidden = !!saved; }
    finally { busy = false; el("policy-fields").disabled = !saved; el("retry-policy").disabled = false; }
  }
  async function load() { await run(async () => restore(await request("/api/v1/policies/credential-egress"))); }
  el("policy-form").addEventListener("submit", event => {
    event.preventDefault();
    run(async () => {
      const scopes = {};
      for (const [kind, field] of [["app", "application_ids"], ["model", "connection_ids"]]) {
        scopes[field] = el(`policy-${kind}-scope`).value === "all" ? [] : selected(kind);
        if (el(`policy-${kind}-scope`).value === "selected" && !scopes[field].length) throw new Error(t("Select at least one item for each selected scope, or choose all."));
      }
      const rules = [el("policy-private-key"), el("policy-api-key")].filter(input => input.checked).map(input => input.value);
      if (!rules.length) throw new Error(t("Select at least one credential detection rule."));
      const input = { revision: saved.revision, mode: el("policy-mode").value, rules, ...scopes };
      restore(await request("/api/v1/policies/credential-egress", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input) }));
      notice(t("Policy saved. New evaluations use revision {revision}.", { revision: saved.revision }));
    });
  });
  for (const id of ["policy-mode", "policy-app-scope", "policy-model-scope"]) el(id).addEventListener("change", render);
  el("reload-policy").addEventListener("click", load);
  el("retry-policy").addEventListener("click", load);
  return {
    async refresh(next) { resources = next; render(); if (!saved) await load(); },
    relocalize: render,
    reset() { saved = null; resources = { applications: [], connections: [] }; el("policy-form").reset(); el("policy-fields").disabled = true; render(); },
  };
}
