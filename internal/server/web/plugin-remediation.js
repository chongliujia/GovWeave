import { t, formatDateTime } from "/i18n.js";

const states = { open: "Open remediation", in_progress: "Remediation in progress", ready_for_recheck: "Ready for recheck", verified: "Verified at recorded snapshot" };
const freshness = { not_verified: "Not verified", current: "Verification matches current evidence", stale: "Evidence changed or expired: recheck required", unavailable: "Verification evidence unavailable" };
const results = { pass: "Requirement satisfied", fail: "Control gap", unknown: "Evidence insufficient / review needed", not_applicable: "Not applicable" };
const node = (tag, text, className) => { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (className) n.className = className; return n; };

export function createPluginRemediation({ request, container }) {
  let product = null, blocked = true, identity = "", generation = 0, busy = false, loaded = false, items = [], selected = null, runs = [], baseline = "";
  let statusKey = "", statusError = "", uncertain = false, evidenceReport = null;
  const panel = node("details", undefined, "plugin-disclosure"); panel.id = "plugin-remediation-panel";
  const heading = node("summary"), hint = node("p", undefined, "field-hint"), status = node("p", undefined, "field-hint"); status.id = "plugin-remediation-status"; status.setAttribute("role", "status");
  const reload = node("button", undefined, "secondary"); reload.type = "button"; reload.id = "plugin-remediation-load";
  const list = node("div"); list.id = "plugin-remediation-list";
  const fields = node("fieldset"); fields.id = "plugin-remediation-fields";
  const title = node("h4"), summary = node("p"), controls = {};
  fields.append(title, summary);
  for (const [key, tag] of [["owner", "input"], ["due", "input"], ["state", "select"], ["note", "textarea"], ["test", "select"]]) {
    const label = node("label", undefined, "plugin-field"), span = node("span"), control = node(tag); control.id = `plugin-remediation-${key}`;
    label.append(span, control); fields.append(label); controls[key] = { span, control };
  }
  controls.owner.control.maxLength = 100; controls.due.control.type = "date"; controls.note.control.maxLength = 2000; controls.note.control.rows = 4;
  const actions = node("div", undefined, "plugin-selection-actions");
  const save = node("button", undefined, "primary"), check = node("button", undefined, "secondary"), tests = node("button", undefined, "secondary"), discard = node("button", undefined, "secondary");
  for (const [button, id] of [[save, "save"], [check, "recheck"], [tests, "tests"], [discard, "discard"]]) { button.type = "button"; button.id = `plugin-remediation-${id}`; actions.append(button); }
  const evidence = node("div"), history = node("div"); evidence.id = "plugin-remediation-evidence"; history.id = "plugin-remediation-history";
  fields.append(actions, evidence, history); panel.append(heading, hint, reload, status, list, fields); container.append(panel);
  const path = () => `/api/v1/compliance/products/${encodeURIComponent(product.id)}/remediations`;
  const signature = () => JSON.stringify([controls.owner.control.value, controls.due.control.value, controls.state.control.value, controls.note.control.value]);
  const dirty = () => !!selected && signature() !== baseline;
  const send = (url, body, method = "POST") => request(url, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  function showStatus(key) { statusKey = key; statusError = ""; uncertain = false; renderStatus(); }
  function renderStatus() { status.textContent = statusKey ? t(statusKey) : t(statusError); if (uncertain) status.textContent += ` ${t("Reload records before retrying; the previous write may have completed.")}`; }
  function renderEvidence() {
    evidence.replaceChildren();
    if (!evidenceReport || !selected) return;
    const control = evidenceReport.snapshot.report.evaluation.controls.find(c => c.id === selected.control_id);
    evidence.append(node("p", `${evidenceReport.summary.id} · ${formatDateTime(evidenceReport.summary.created_at)} · ${t(results[control.status])}`), node("p", t("Retained evidence is historical; it does not replace a current recheck.")));
    for (const ref of control.evidence) evidence.append(node("p", `${ref.fact} · ${ref.source} · ${ref.evidence_id}`));
  }
  function update() {
    reload.disabled = !product || blocked || busy;
    fields.hidden = !selected; fields.disabled = !selected || blocked || busy || !loaded;
    save.disabled = !dirty() || controls.state.control.value === "verified"; discard.disabled = !dirty();
    check.disabled = dirty() || selected?.current.status !== "ready_for_recheck";
    for (const button of list.querySelectorAll("button")) button.disabled = busy || blocked;
  }
  function localize() {
    heading.textContent = t("Remediation and verification"); reload.textContent = t("Load remediations and retests");
    hint.textContent = t("Track a control gap from its assessment. Record the fix, mark it ready, then recheck current evidence. Model calls require a separate explicit test run. Keep secrets and response bodies out of notes.");
    const labels = { owner: "Responsible person or team", due: "Target date", state: "Remediation status", note: "Remediation note", test: "Optional completed retest" };
    for (const [key, label] of Object.entries(labels)) controls[key].span.textContent = t(label);
    save.textContent = t("Save remediation progress"); check.textContent = t("Recheck evidence and verify"); tests.textContent = t("Open model tests"); discard.textContent = t("Discard changes");
    const state = controls.state.control.value, run = controls.test.control.value;
    controls.state.control.replaceChildren(...Object.entries(states).map(([value, label]) => { const option = node("option", t(label)); option.value = value; option.disabled = value === "verified" || selected?.current.status === "verified" && value !== "open"; return option; })); controls.state.control.value = state;
    const none = node("option", t("Recheck saved evidence without attaching a model test")); none.value = "";
    controls.test.control.replaceChildren(none, ...runs.filter(r => r.state === "completed").map(r => { const option = node("option", `${r.id} · ${r.status} · ${formatDateTime(r.started_at)}`); option.value = r.id; return option; })); controls.test.control.value = run;
    renderList(); if (selected) renderDetails(); renderStatus(); renderEvidence(); update();
  }
  function renderList() {
    list.replaceChildren();
    if (loaded && !items.length) list.append(node("p", t("No remediations recorded for this product. Use Track remediation on a control gap."), "field-hint"));
    for (const item of items) {
      const button = node("button", `${item.control_id} · ${item.title} · ${t(states[item.current.status])} · ${t(freshness[item.verification_state])}`, "secondary");
      button.type = "button"; button.dataset.remediation = item.id;
      button.addEventListener("click", () => { if (dirty() && !window.confirm(t("Discard unsaved remediation changes?"))) return; select(item); });
      list.append(button);
    }
  }
  function reference(parent, id, label) {
    const button = node("button", t(label), "text-button"); button.type = "button";
    button.addEventListener("click", () => action(async token => {
      const report = await request(`/api/v1/compliance/reports/${encodeURIComponent(id)}`);
      if (token !== generation) return;
      evidenceReport = report; renderEvidence();
    })); parent.append(button);
  }
  function renderDetails() {
    title.textContent = `${selected.control_id} · ${selected.title}`;
    summary.textContent = `${t(states[selected.current.status])} · ${t(freshness[selected.verification_state])} · ${selected.id}`;
    history.replaceChildren(node("h5", t("Remediation history")));
    reference(history, selected.source_report_id, "View original finding");
    for (const event of selected.events) {
      const row = node("div", undefined, "plugin-evidence-reference");
      row.append(node("p", `${event.revision} · ${formatDateTime(event.at)} · ${t(states[event.status])}`), node("p", event.owner), node("p", event.due_date), node("p", event.note));
      if (event.verification) {
        row.append(node("p", `${t("Recheck result")}: ${t(results[event.verification.result])}`));
        reference(row, event.verification.report_id, "View verification report");
        if (event.verification.test_run_id) row.append(node("p", `${t("Linked retest")}: ${event.verification.test_run_id}`));
      }
      history.append(row);
    }
  }
  function select(item) {
    selected = item; evidenceReport = null; evidence.replaceChildren();
    controls.owner.control.value = item.current.owner; controls.due.control.value = item.current.due_date;
    controls.note.control.value = item.current.note;
    localize(); controls.state.control.value = item.current.status; controls.test.control.value = "";
    baseline = signature(); update();
  }
  async function action(task, mutation = false) {
    if (busy || !product || blocked) return;
    const token = generation; busy = true; update();
    try { await task(token); }
    catch (error) { if (token === generation) { statusKey = ""; statusError = error.message; uncertain = mutation; if (mutation) loaded = false; renderStatus(); } }
    finally { if (token === generation) { busy = false; update(); } }
  }
  async function load() {
    if (dirty() && !window.confirm(t("Discard unsaved remediation changes?"))) return;
    await action(async token => {
      const previousID = selected?.id;
      loaded = false; selected = null; items = []; evidenceReport = null; list.replaceChildren(); evidence.replaceChildren(); history.replaceChildren(); update(); showStatus("Loading remediations…");
      const [records, tests] = await Promise.all([request(path()), request(`/api/v1/compliance/products/${encodeURIComponent(product.id)}/test-runs`)]);
      if (token !== generation) return;
      items = records.remediations; runs = tests.runs; loaded = true;
      const keep = items.find(item => item.id === previousID);
      localize(); if (keep) select(keep);
      showStatus("Records loaded. Verification reflects the evidence checked at this read; reload after changes.");
    });
  }
  save.addEventListener("click", () => action(async token => {
    const saved = await send(`${path()}/${encodeURIComponent(selected.id)}`, { revision: selected.current.revision, status: controls.state.control.value, owner: controls.owner.control.value.trim(), due_date: controls.due.control.value, note: controls.note.control.value.trim() }, "PUT");
    if (token !== generation) return;
    items = items.map(item => item.id === saved.id ? saved : item); select(saved); showStatus("Progress saved. Marking a fix ready does not verify it.");
  }, true));
  check.addEventListener("click", () => action(async token => {
    if (dirty() || selected.current.status !== "ready_for_recheck") return;
    const saved = await send(`${path()}/${encodeURIComponent(selected.id)}/recheck`, { revision: selected.current.revision, test_run_id: controls.test.control.value });
    if (token !== generation) return;
    items = items.map(item => item.id === saved.id ? saved : item); select(saved);
    showStatus(saved.current.status === "verified" ? "Verification recorded. Scope, configuration and evidence changes require a new recheck." : "Recheck did not pass. The remediation remains in progress; inspect the retained report.");
  }, true));
  tests.addEventListener("click", () => { const panel = document.getElementById("plugin-tests-panel"); panel.open = true; panel.scrollIntoView({ block: "start" }); });
  discard.addEventListener("click", () => select(selected)); reload.addEventListener("click", load);
  fields.addEventListener("input", update); fields.addEventListener("change", update);
  localize();
  return {
    isDirty: dirty,
    create(controlID) {
      panel.open = true; panel.scrollIntoView({ block: "start" });
      if (dirty() && !window.confirm(t("Discard unsaved remediation changes?"))) return;
      return action(async token => {
        const base = path(), pid = product.id;
        const archive = await send(`/api/v1/compliance/products/${encodeURIComponent(pid)}/reports`, {});
        if (token !== generation) return;
        const item = await send(base, { report_id: archive.summary.id, control_id: controlID, owner: "", due_date: "", note: "" });
        if (token !== generation) return;
        const records = await request(base); if (token !== generation) return;
        items = records.remediations; loaded = true; select(item);
        showStatus("Remediation created from a retained assessment. Add an owner and describe the intended fix.");
      }, true);
    },
    sync(next) {
      const key = JSON.stringify([next.product?.id, next.product?.revision, next.dirty, next.policyRevision]);
      product = next.product; blocked = !product || next.dirty;
      if (key !== identity) {
        generation++; identity = key; busy = loaded = false; selected = null; evidenceReport = null; items = []; runs = []; baseline = "";
        for (const c of Object.values(controls)) c.control.value = "";
        list.replaceChildren(); history.replaceChildren(); evidence.replaceChildren();
        showStatus("Select a saved product and load its remediations.");
      }
      localize();
    },
    relocalize: localize,
    reset() { this.sync({ product: null, dirty: false }); panel.open = false; },
  };
}
