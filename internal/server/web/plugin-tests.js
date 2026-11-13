import { t, formatDateTime } from "/i18n.js";

const node = (tag, text) => {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  return element;
};

export function modelTargets(product, resources) {
  return (resources?.applications || []).filter(application => !application.revoked && product?.application_ids?.includes(application.id)).flatMap(application =>
    (resources.connections || []).filter(connection => connection.enabled && application.allowed_connections?.includes(connection.id)).map(connection => ({
      application_id: application.id, model_alias: connection.alias, label: `${application.name} / ${connection.alias}`,
    })));
}

export function createPluginTests({ request, container }) {
  let product = null, resources = null, dirty = false, identity = "", generation = 0, busy = false, loaded = false;
  let plan = null, suites = [], runs = [], targets = [], baseline = "";
  const panel = node("details"); panel.className = "plugin-disclosure"; panel.id = "plugin-tests-panel";
  const heading = node("summary"), hint = node("p"), status = node("p");
  hint.className = status.className = "field-hint"; status.setAttribute("role", "status"); status.id = "plugin-tests-status";
  const reload = node("button"); reload.type = "button"; reload.id = "plugin-tests-load"; reload.className = "secondary";
  const fields = node("fieldset"); fields.id = "plugin-tests-fields";
  const controls = {};
  for (const [key, tag] of [["target", "select"], ["suite", "select"], ["version", "input"], ["context", "textarea"]]) {
    const wrapper = node("label"), title = node("span"), control = node(tag);
    wrapper.className = "plugin-field"; control.id = `plugin-tests-${key}`;
    wrapper.append(title, control); fields.append(wrapper); controls[key] = { title, control };
  }
  controls.version.control.maxLength = 100; controls.context.control.maxLength = 1000;
  const save = node("button"); save.type = "button"; save.id = "plugin-tests-save"; save.className = "primary";
  const consentLabel = node("label"), consent = node("input"), consentText = node("span");
  consent.type = "checkbox"; consent.id = "plugin-tests-consent"; consentLabel.className = "check-line"; consentLabel.append(consent, consentText);
  const actions = node("div"); actions.className = "plugin-selection-actions";
  const startButtons = ["pre_deployment", "operation"].map(phase => {
    const button = node("button"); button.type = "button"; button.id = `plugin-tests-${phase}`; button.className = "secondary";
    button.addEventListener("click", () => start(phase)); actions.append(button); return button;
  });
  fields.append(save, consentLabel, actions);
  const history = node("div"), detail = node("div"); history.id = "plugin-tests-history"; detail.id = "plugin-tests-detail";
  panel.append(heading, hint, reload, status, fields, history, detail); container.append(panel);
  const fingerprint = () => JSON.stringify(Object.values(controls).map(item => item.control.value));
  function update() {
    reload.disabled = !product || dirty || busy;
    fields.disabled = !product || dirty || busy || !loaded;
    save.disabled = !targets.length || !suites.length;
    for (const button of startButtons) button.disabled = !plan || !targets[controls.target.control.value] || !suites[controls.suite.control.value] || !consent.checked || fingerprint() !== baseline || runs.some(run => run.state === "running");
  }
  function localize() {
    heading.textContent = t("Model tests and retained history");
    hint.textContent = t("This instance only. Isolated test reports are not imported automatically. Tests can incur provider charges; they do not establish legal compliance.");
    reload.textContent = t("Load test plans and history");
    const labels = { target: "Authorized model target", suite: "Installed test suite", version: "Test target version", context: "Test scope and limitations" };
    for (const [key, value] of Object.entries(labels)) controls[key].title.textContent = t(value);
    save.textContent = t("Save model test plan"); consentText.textContent = t("I authorize synthetic model calls for this test run.");
    startButtons[0].textContent = t("Run pre-deployment tests"); startButtons[1].textContent = t("Run operation tests");
    if (!product || dirty) status.textContent = t("Save and select a product before loading tests.");
    update();
  }
  async function action(task) {
    if (busy || !product || dirty) return;
    const token = generation; busy = true; update();
    try { await task(token); }
    catch (error) { if (token === generation) status.textContent = error.message; }
    finally { if (token === generation) { busy = false; update(); } }
  }
  function renderHistory() {
    history.replaceChildren();
    if (!runs.length) history.append(node("p", t("No retained tests in this instance for the selected product. Local reports do not appear here.")));
    for (const run of runs) {
      const row = node("p"), button = node("button", `${formatDateTime(run.started_at)} · ${run.phase} · ${run.state} · ${run.status}`);
      button.className = "secondary";
      button.type = "button"; button.dataset.testRun = run.id;
      button.addEventListener("click", () => action(async token => {
        const result = await request(`/api/v1/compliance/test-runs/${encodeURIComponent(run.id)}`);
        if (token !== generation) return;
        detail.replaceChildren(node("h4", t("Retained test snapshot")), node("p", `${result.id} · ${result.status}`));
        detail.append(node("p", t("Historical results are not a current verdict. Unknown and inconclusive are not pass.")));
        for (const item of result.cases || []) {
          detail.append(node("p", `${item.case_id} · ${item.status} · ${item.reason} · HTTP ${item.http_status} · ${item.duration_ms} ms`));
        }
      }));
      row.append(button); history.append(row);
    }
  }
  async function load() {
    await action(async token => {
      const path = `/api/v1/compliance/products/${encodeURIComponent(product.id)}`;
      loaded = false; detail.replaceChildren(); status.textContent = t("Loading tests…");
      const [saved, catalog, records] = await Promise.all([request(path + "/test-plans"), request("/api/v1/compliance/test-suites"), request(path + "/test-runs")]);
      if (token !== generation) return;
      plan = (saved.plans || []).find(item => !item.target_kind) || null;
      suites = catalog.suites || []; runs = records.runs || []; targets = modelTargets(product, resources);
      for (const [key, entries] of [["target", targets.map((target, index) => [String(index), target.label])], ["suite", suites.map((suite, index) => [String(index), `${suite.name} / ${suite.version} (${suite.cases})`])]]) {
        controls[key].control.replaceChildren(...entries.map(([value, text]) => { const option = node("option", text); option.value = value; return option; }));
      }
      if (plan) {
        controls.target.control.value = String(targets.findIndex(target => target.application_id === plan.application_id && target.model_alias === plan.model_alias));
        controls.suite.control.value = String(suites.findIndex(suite => suite.id === plan.suite_id && suite.version === plan.suite_version));
      }
      controls.version.control.value = plan?.target_version || ""; controls.context.control.value = plan?.context || "";
      baseline = fingerprint(); consent.checked = false; loaded = true; renderHistory();
      status.textContent = t("Loaded instance records. Saving a plan does not run it. Response text is not retained; existing schedules are preserved.");
    });
  }
  save.addEventListener("click", () => action(async token => {
    const target = targets[controls.target.control.value], suite = suites[controls.suite.control.value];
    if (!target || !suite || !controls.version.control.value.trim() || !controls.context.control.value.trim()) throw new Error(t("Choose a target and suite, and provide a version and test scope."));
    const productID = product.id, planID = plan?.plan_id || (plan ? "" : "model");
    const definition = await request(`/api/v1/compliance/test-suites/${encodeURIComponent(suite.id)}/versions/${encodeURIComponent(suite.version)}`);
    if (token !== generation) return;
    if (definition.target_kind) throw new Error(t("Select a model test suite, not a read-tool suite."));
    const body = { revision: plan?.revision || 0, ...target, target_version: controls.version.control.value.trim(), context: controls.context.control.value.trim(),
      suite_id: suite.id, suite_version: suite.version, schedule_enabled: plan?.schedule_enabled || false,
      interval_seconds: plan?.interval_seconds || 300, timeout_seconds: 30, max_output_tokens: 128, retain_responses: false };
    delete body.label;
    const suffix = planID ? `/test-plans/${planID}` : "/test-plan";
    const saved = await request(`/api/v1/compliance/products/${encodeURIComponent(productID)}${suffix}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (token !== generation) return;
    plan = saved; baseline = fingerprint(); consent.checked = false;
    status.textContent = t("Test plan saved. Select a phase to explicitly start model calls.");
  }));
  async function start(phase) {
    if (!plan || !consent.checked || fingerprint() !== baseline) return;
    await action(async token => {
      consent.checked = false;
      status.textContent = t("Submitting test run…");
      try {
        const run = await request(`/api/v1/compliance/products/${encodeURIComponent(product.id)}/test-runs`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ phase, plan_id: plan.plan_id || "" }) });
        if (token !== generation) return;
        runs = [run, ...runs.filter(item => item.id !== run.id)]; renderHistory();
        status.textContent = t("Test accepted, not finished. Reload history to inspect completion; do not submit another run.");
      } catch (error) {
        if (token === generation) { loaded = false; status.textContent = t("Submission outcome is uncertain. Reload history before retrying; a run may already exist."); }
      }
    });
  }
  reload.addEventListener("click", load);
  fields.addEventListener("input", update); fields.addEventListener("change", update);
  localize();
  return {
    sync(next) {
      const key = JSON.stringify([next.product?.id, next.product?.revision, next.dirty, next.resources?.revision]);
      product = next.product; resources = next.resources; dirty = next.dirty;
      if (key !== identity) {
        generation++; identity = key; busy = loaded = false; plan = null; runs = []; consent.checked = false;
        history.replaceChildren(); detail.replaceChildren(); status.textContent = t("Load test plans and history");
        for (const item of Object.values(controls)) { if (item.control.tagName === "SELECT") item.control.replaceChildren(); else item.control.value = ""; }
      }
      localize();
    },
    relocalize() { localize(); if (loaded) renderHistory(); },
    reset() { this.sync({ product: null, resources: null, dirty: false }); panel.open = false; },
  };
}
