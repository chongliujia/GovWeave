import { t } from "/i18n.js";

const node = (tag, text, className) => {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
};
const label = (tag, key, className) => { const el = node(tag, t(key), className); el.dataset.pluginLabel = key; return el; };
const reserved = (key, source) => /^(runtime|testing)\./.test(key) || source === "runtime";

export function collectEvidenceFields(pack) {
  const fields = new Map();
  function visit(expression, control) {
    if (!expression) return;
    if (expression.fact && !fields.has(expression.fact)) fields.set(expression.fact, {
      key: expression.fact, source: expression.source || "declared", type: typeof expression.value === "number" ? "number" : typeof expression.value === "string" ? "string" : "boolean",
      title: control.title, automatic: reserved(expression.fact, expression.source),
    });
    for (const child of [...(expression.all || []), ...(expression.any || []), ...(expression.not ? [expression.not] : [])]) visit(child, control);
  }
  for (const control of pack.controls) { visit(control.applies_when, control); visit(control.requirement, control); }
  return [...fields.values()];
}

export function parseEvidenceDraft(key, raw) {
  if (reserved(key, raw.source)) throw new Error(t("Runtime and test evidence is collected by the server."));
  if (!raw.present) return null;
  const fail = () => { throw new Error(t("Complete the value, source, reference ID and ISO timestamp for {fact}.", { fact: key })); };
  let value;
  if (raw.type === "boolean") { if (!["true", "false"].includes(raw.value)) fail(); value = raw.value === "true"; }
  else if (raw.type === "number") { if (!raw.value.trim() || !Number.isFinite(Number(raw.value))) fail(); value = Number(raw.value); }
  else if (raw.type === "string" && raw.value.length <= 512) value = raw.value;
  else fail();
  const timestamp = v => /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/.test(v) && Number.isFinite(Date.parse(v));
  if (!["assessment", "document", "declared"].includes(raw.source) || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/.test(raw.evidence_id) || !timestamp(raw.observed_at) || raw.expires_at && (!timestamp(raw.expires_at) || Date.parse(raw.expires_at) <= Date.parse(raw.observed_at))) fail();
  return { value, source: raw.source, evidence_id: raw.evidence_id, observed_at: raw.observed_at, ...(raw.expires_at ? { expires_at: raw.expires_at } : {}) };
}

export function createPluginEvidence({ request, container, onChange }) {
  let identity = "", generation = 0, descriptor = null, definition = null, base = {}, edits = new Map(), loading = false, failed = false;
  const panel = node("details", undefined, "plugin-disclosure"); panel.id = "plugin-evidence-panel";
  panel.append(label("summary", "Evidence references"), label("p", "Add references to your assessments and documents. These are operator-supplied claims, not uploaded or independently verified documents. Manual review never passes automatically. Do not enter document bodies or secrets.", "field-hint"));
  const status = node("p", undefined, "field-hint"); status.id = "plugin-evidence-status"; status.setAttribute("role", "status");
  const retry = label("button", "Reload evidence requirements", "secondary"); retry.type = "button";
  const list = node("div", undefined, "plugin-evidence-fields"); panel.append(status, retry, list); container.append(panel);
  retry.addEventListener("click", () => load());
  function rawFor(field) {
    if (edits.has(field.key)) return edits.get(field.key);
    const saved = base[field.key];
    return { present: !!saved, type: saved ? typeof saved.value : field.type, value: saved ? String(saved.value) : "", source: saved?.source || field.source, evidence_id: saved?.evidence_id || "", observed_at: saved?.observed_at || "", expires_at: saved?.expires_at || "" };
  }
  function render() {
    const opened = new Set([...list.querySelectorAll("details[open]")].map(el => el.dataset.fact));
    list.replaceChildren(); retry.hidden = !failed; retry.disabled = loading;
    status.textContent = !descriptor ? t("Select a framework to see its evidence requirements.") : loading ? t("Loading evidence requirements…") : failed ? t("Evidence requirements unavailable. Retry; your draft references are preserved.") : t("References are saved with the product. Unchecked facts are absent; absence is not a pass.");
    if (!definition) return;
    for (const field of collectEvidenceFields(definition)) {
      const row = node("details", undefined, "plugin-evidence-editor"); row.dataset.fact = field.key; row.open = opened.has(field.key);
      row.append(node("summary", field.key), node("p", field.title, "field-hint"));
      if (field.automatic) { row.append(label("p", "Runtime and test evidence is collected by the server.", "field-hint")); list.append(row); continue; }
      const raw = rawFor(field), enable = node("input"); enable.type = "checkbox"; enable.checked = raw.present; enable.dataset.evidenceField = "present";
      const enableLabel = node("label", undefined, "check-line"); enableLabel.append(enable, label("span", "Include this evidence reference")); row.append(enableLabel);
      const fields = node("fieldset", undefined, "plugin-evidence-inputs"); fields.disabled = !raw.present;
      const inputs = {};
      function input(key, title, choices) {
        const wrapper = node("label", undefined, "plugin-field"), control = node(choices ? "select" : "input");
        wrapper.append(label("span", title), control); fields.append(wrapper); control.dataset.evidenceField = key; inputs[key] = control;
        if (choices) for (const [value, text] of choices) { const option = node("option", t(text)); option.value = value; control.append(option); }
        else { control.type = "text"; control.maxLength = key === "value" ? 512 : 100; }
        control.value = raw[key]; return control;
      }
      input("type", "Value type", [["boolean", "Yes / no"], ["string", "Text value"], ["number", "Number value"]]);
      input("value", "Evidence value", raw.type === "boolean" ? [["", "Choose a value"], ["true", "Yes"], ["false", "No"]] : null);
      input("source", "Evidence source", [["assessment", "Assessment reference"], ["document", "Document reference"], ["declared", "Operator declaration (not independently verified)"]]);
      input("evidence_id", "Evidence reference ID");
      input("observed_at", "Observed at (ISO timestamp)").placeholder = "2026-11-15T09:00:00Z";
      input("expires_at", "Expires at (optional ISO timestamp)").placeholder = "2026-12-15T09:00:00Z";
      function update(event) {
        const next = { present: enable.checked, ...Object.fromEntries(Object.entries(inputs).map(([key, input]) => [key, input.value])) };
        if (event.target === inputs.type) next.value = "";
        edits.set(field.key, next); fields.disabled = !enable.checked;
        if (event.target === inputs.type) render();
        onChange();
      }
      row.addEventListener("input", update); row.addEventListener("change", update);
      row.append(fields); list.append(row);
    }
  }
  async function load() {
    if (!descriptor || loading) return;
    const token = ++generation, requested = descriptor; loading = true; failed = false; definition = null; render();
    try {
      const next = await request(`/api/v1/compliance/packs/${encodeURIComponent(requested.id)}/versions/${encodeURIComponent(requested.version)}`);
      if (token !== generation) return;
      if (next.id !== requested.id || next.version !== requested.version) throw new Error("pack identity mismatch");
      definition = next;
    } catch { if (token === generation) failed = true; }
    finally { if (token === generation) { loading = false; render(); } }
  }
  return {
    sync(pack) {
      const key = pack ? JSON.stringify([pack.id, pack.version, pack.sha256]) : "";
      if (key === identity) return;
      generation++; identity = key; descriptor = pack; loading = failed = false; definition = null; render(); if (pack) load();
    },
    restore(facts) { base = structuredClone(facts || {}); edits = new Map(); render(); },
    signature() { return JSON.stringify([...edits]); },
    facts() {
      const result = structuredClone(base);
      for (const [key, raw] of edits) {
        try { const fact = parseEvidenceDraft(key, raw); if (fact) result[key] = fact; else delete result[key]; }
        catch (error) {
          panel.open = true;
          const row = [...list.children].find(el => el.dataset.fact === key);
          if (row) { row.open = true; row.querySelector("input, select")?.focus(); }
          throw error;
        }
      }
      return result;
    },
    relocalize: render,
    reset() { generation++; identity = ""; descriptor = definition = null; base = {}; edits = new Map(); loading = failed = false; panel.open = false; render(); },
  };
}
