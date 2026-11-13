import { t, formatDateTime } from "/i18n.js";

const controlStates = { pass: "Requirement satisfied", fail: "Control gap", unknown: "Evidence insufficient / review needed", not_applicable: "Not applicable" };
const reasons = { outside_effective_window: "Outside the rule pack's effective window", outside_scope: "Outside the declared applicability conditions", applicability_unknown: "Applicability needs evidence or review", requirement_satisfied: "The supplied evidence satisfies this technical requirement", requirement_not_satisfied: "The supplied evidence does not satisfy this requirement", insufficient_evidence: "Required evidence is missing or unsuitable", manual_review_required: "Qualified manual review is still required" };
const issueLabels = { missing_evidence: "Missing evidence", future_evidence: "Evidence observation time is in the future", stale_evidence: "Evidence exceeds the required age limit", expired_evidence: "Evidence has expired", source_mismatch: "Evidence source does not match the requirement", type_mismatch: "Evidence value has an incompatible type" };
const sources = { declared: "Operator declaration (not independently verified)", runtime: "Runtime observation", document: "Document reference", assessment: "Assessment reference" };
const methods = { evidence: "Evidence-based technical check", manual: "Manual review required" };
const bases = { legal_obligation: "Publisher-declared legal obligation", supporting_practice: "Supporting practice" };
const filters = { all: "All control results", attention: "Needs attention", pass: "Requirement satisfied", fail: "Control gap", unknown: "Evidence insufficient / review needed", not_applicable: "Not applicable", manual: "Awaiting manual review" };
const severities = { low: "Low severity", medium: "Medium severity", high: "High severity", critical: "Critical severity" };
const defaultActions = { "Correct the failed technical control and provide current verification evidence.": "Correct the failed technical control and provide current verification evidence.", "Have a qualified reviewer assess applicability or the interpretive requirement and retain their evidence.": "Have a qualified reviewer assess applicability or the interpretive requirement and retain their evidence.", "Supply current evidence of the expected type and source, then reassess.": "Supply current evidence of the expected type and source, then reassess." };
const node = (tag, text, className) => {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
};
const message = (tag, key, className) => {
  const element = node(tag, t(key), className); element.dataset.pluginLabel = key; return element;
};
const stamp = value => value ? formatDateTime(value) : t("Not supplied");
const controlStatus = control => Object.hasOwn(controlStates, control.status) ? control.status : "unknown";

export function summarizeControls(controls) {
  const counts = { pass: 0, fail: 0, unknown: 0, not_applicable: 0 };
  for (const control of controls) counts[controlStatus(control)]++;
  return counts;
}

export function assessmentMatches(report, product, pack) {
  if (!product || report.product_id !== product.id || report.product_revision !== product.revision) return false;
  if (report.state !== "ready") return !report.evaluation;
  const evaluation = report.evaluation;
  return !!pack && !!evaluation && evaluation.product_id === product.id && evaluation.product_version === product.version &&
    evaluation.pack_id === product.pack_id && evaluation.pack_version === product.pack_version &&
    pack.id === product.pack_id && pack.version === product.pack_version && evaluation.pack_sha256 === pack.sha256;
}

export function safeSourceURL(value) {
  try {
    const url = new URL(value);
    return ["https:", "http:"].includes(url.protocol) && !url.username && !url.password ? url.href : null;
  } catch { return null; }
}

export function createPluginAssessment({ request, packContainer, reportContainer }) {
  let descriptor = null, product = null, dirty = false, definition = null, report = null;
  let packIdentity = "", productIdentity = "", packToken = 0, loading = false, packError = false, reportMessage = "", expiryTimer;
  const packPanel = node("details", undefined, "plugin-disclosure"); packPanel.id = "plugin-pack-inspect";
  packPanel.append(message("summary", "Rule pack coverage and sources"));
  const packReload = message("button", "Load rule pack details", "secondary"); packReload.type = "button"; packReload.id = "plugin-pack-load";
  const packStatus = node("p", undefined, "field-hint"); packStatus.id = "plugin-pack-load-status"; packStatus.setAttribute("role", "status");
  const packBody = node("div", undefined, "plugin-pack-definition"); packBody.id = "plugin-pack-definition";
  packPanel.append(packReload, packStatus, packBody); packContainer.append(packPanel);
  const reportStatus = node("p", undefined, "plugin-boundary"); reportStatus.id = "plugin-assessment-status"; reportStatus.setAttribute("role", "status");
  const reportBody = node("div"); reportBody.id = "plugin-assessment-body";
  const toolbar = node("div", undefined, "plugin-assessment-toolbar");
  const searchLabel = node("label", undefined, "plugin-field"), search = node("input"); search.type = "search"; search.id = "plugin-control-search";
  searchLabel.append(message("span", "Search control IDs, titles or evidence facts"), search);
  const filterLabel = node("label", undefined, "plugin-field"), filter = node("select"); filter.id = "plugin-control-filter";
  filterLabel.append(message("span", "Control result filter"), filter); toolbar.append(searchLabel, filterLabel);
  const count = node("p", undefined, "field-hint"); count.id = "plugin-control-count"; count.setAttribute("role", "status");
  const controls = node("div", undefined, "plugin-control-list"); controls.id = "plugin-control-results";
  reportContainer.append(reportStatus, reportBody, toolbar, count, controls);
  search.addEventListener("input", renderControls); filter.addEventListener("change", renderControls);
  packReload.addEventListener("click", loadPack);
  packPanel.addEventListener("toggle", () => { if (packPanel.open && !definition && !loading && !packError) loadPack(); });

  function info(parent, title, value) {
    const row = node("p", undefined, "plugin-assessment-info"); row.append(node("strong", `${t(title)}: `), node("span", value || t("Not supplied"))); parent.append(row);
  }
  function list(parent, title, values, fallback) {
    parent.append(node("h5", t(title)));
    if (!values?.length) { parent.append(node("p", t(fallback), "field-hint")); return; }
    const items = node("ul"); for (const value of values) items.append(node("li", value)); parent.append(items);
  }
  function expression(parent, title, value) {
    if (!value) return;
    const details = node("details", undefined, "plugin-expression"); details.append(node("summary", t(title)), node("pre", JSON.stringify(value, null, 2))); parent.append(details);
  }
  function renderPack() {
    packReload.disabled = !descriptor || loading;
    packStatus.textContent = !descriptor ? t("Select an installed rule pack to view its definition.") : loading ? t("Loading rule pack details…") : packError ? t("Rule pack details unavailable. Retry without changing your selection.") : "";
    packBody.replaceChildren();
    if (!definition) return;
    packBody.append(node("h4", definition.name));
    info(packBody, "Pinned rule pack", `${definition.id} · ${definition.version}`);
    info(packBody, "Definition fingerprint", descriptor.sha256);
    info(packBody, "Declared coverage", definition.description || t("Coverage is not declared. Do not infer complete framework coverage."));
    info(packBody, "Publisher review status", definition.review.status === "reviewed" ? t("Reviewed (publisher declaration)") : t("Draft pack"));
    info(packBody, "Declared reviewer", definition.review.reviewer);
    info(packBody, "Declared review time", stamp(definition.review.reviewed_at));
    info(packBody, "Effective from", stamp(definition.effective_from)); info(packBody, "Effective until", stamp(definition.effective_to));
    packBody.append(message("p", "Publisher metadata is not independent approval or certification. Missing scope or limitations do not mean complete coverage.", "plugin-boundary"));
    list(packBody, "Limitations and exclusions", definition.limitations, "No limitations are declared by this pack; coverage remains unverified.");
    packBody.append(message("h5", "Source versions"));
    for (const source of definition.sources) {
      const item = node("div", undefined, "plugin-source"); item.append(node("strong", source.title));
      info(item, "Source version", source.version); info(item, "Source checked on", source.checked_on);
      if (source.url) {
        const href = safeSourceURL(source.url);
        if (href) { const link = node("a", source.url); link.href = href; link.target = "_blank"; link.rel = "noopener noreferrer"; item.append(link); }
        else info(item, "Source URL (not opened)", source.url);
      }
      packBody.append(item);
    }
    packBody.append(node("h5", t("Control definitions: {count}", { count: definition.controls.length })));
    for (const control of definition.controls) {
      const item = node("details", undefined, "plugin-control-definition"); item.append(node("summary", `${control.id} · ${control.title}`));
      info(item, "Citation", control.citation); info(item, "Severity", t(severities[control.severity] || control.severity));
      info(item, "Assessment method", t(methods[control.assessment_method || "evidence"] || control.assessment_method));
      info(item, "Basis", control.basis ? t(bases[control.basis] || control.basis) : ""); info(item, "Declared remediation", control.remediation);
      expression(item, "Applicability expression", control.applies_when); expression(item, "Requirement expression", control.requirement);
      packBody.append(item);
    }
  }
  async function loadPack() {
    if (!descriptor || loading) return;
    const token = ++packToken, requested = descriptor;
    loading = true; packError = false; definition = null; renderPack();
    try {
      const next = await request(`/api/v1/compliance/packs/${encodeURIComponent(requested.id)}/versions/${encodeURIComponent(requested.version)}`);
      if (token !== packToken) return;
      if (next.id !== requested.id || next.version !== requested.version) throw new Error("Rule pack identity mismatch");
      definition = next;
    } catch { if (token === packToken) packError = true; }
    finally { if (token === packToken) { loading = false; renderPack(); } }
  }
  function renderControls() {
    const all = report?.state === "ready" ? report.evaluation.controls : [];
    const query = search.value.trim().toLowerCase(), selected = filter.value || "all";
    const shown = all.filter(control => {
      const status = controlStatus(control);
      const match = selected === "all" || selected === status || selected === "attention" && ["fail", "unknown"].includes(status) || selected === "manual" && control.reason === "manual_review_required";
      return match && [control.id, control.title, control.citation, ...control.issues.map(issue => issue.fact), ...control.evidence.map(evidence => evidence.fact)].join(" ").toLowerCase().includes(query);
    });
    const open = new Set([...controls.querySelectorAll("details[open]")].map(item => item.dataset.controlId));
    controls.replaceChildren(); count.textContent = t("Showing {shown} of {total} control results", { shown: shown.length, total: all.length });
    if (!shown.length) controls.append(message("p", "No control results match this filter.", "field-hint"));
    for (const control of shown) {
      const item = node("details", undefined, "plugin-control-result"), status = controlStatus(control);
      item.dataset.controlId = control.id; item.dataset.status = status; item.open = open.has(control.id);
      const summary = node("summary"), badge = node("span", t(controlStates[status]), "plugin-control-badge");
      summary.append(badge, node("strong", `${control.id} · ${control.title}`), node("span", t(reasons[control.reason] || control.reason), "plugin-control-reason")); item.append(summary);
      info(item, "Citation", control.citation); info(item, "Severity", t(severities[control.severity] || control.severity));
      info(item, "Assessment method", t(methods[control.assessment_method] || control.assessment_method)); info(item, "Basis", control.basis ? t(bases[control.basis] || control.basis) : "");
      list(item, "Evidence problems to resolve", control.issues.map(issue => `${issue.fact} · ${t(issueLabels[issue.code] || issue.code)}`), "No evidence issues were recorded for this control.");
      const findings = report.evaluation.findings.filter(finding => finding.control_id === control.id);
      list(item, "Next actions", findings.map(finding => Object.hasOwn(defaultActions, finding.action) ? t(defaultActions[finding.action]) : finding.action), "No next action was recorded; this is not a legal compliance conclusion.");
      item.append(message("h5", "Evidence references"));
      if (!control.evidence.length) item.append(message("p", "No evidence references were recorded.", "field-hint"));
      for (const evidence of control.evidence) {
        const reference = node("div", undefined, "plugin-evidence-reference");
        info(reference, "Evidence fact", evidence.fact); info(reference, "Evidence ID", evidence.evidence_id);
        info(reference, "Evidence source", t(sources[evidence.source] || evidence.source));
        info(reference, "Observed at", stamp(evidence.observed_at)); info(reference, "Expires at", stamp(evidence.expires_at)); item.append(reference);
      }
      controls.append(item);
    }
  }
  function renderReport() {
    clearTimeout(expiryTimer);
    const ready = report?.state === "ready" && report.evaluation.controls.length > 0;
    toolbar.hidden = count.hidden = controls.hidden = !ready;
    reportBody.replaceChildren();
    if (!ready) controls.replaceChildren();
    if (dirty || !product || !report) {
      reportStatus.textContent = dirty ? t("Save or discard product changes before assessing. Previous results are hidden.") : !product ? t("Save or select a product to view its assessment.") : reportMessage ? t(reportMessage) : t("Load the latest assessment or evaluate the saved product.");
      return;
    }
    if (report.state !== "ready") {
      reportStatus.textContent = report.state === "pending" ? t("Assessment pending. No previous results are presented as current.") : t("Assessment unavailable. No pass result can be inferred.");
      return;
    }
    const evaluation = report.evaluation;
    reportStatus.textContent = t("Assessment snapshot — not a live compliance verdict or certification.");
    const deadline = Date.parse(report.next_refresh_at || evaluation.reevaluate_at);
    if (Number.isFinite(deadline)) {
      if (Date.now() >= deadline) reportStatus.textContent += ` ${t("This snapshot needs refreshing. Load the latest assessment or evaluate again.")}`;
      else expiryTimer = setTimeout(renderReport, Math.min(deadline - Date.now() + 20, 2147483647));
    }
    info(reportBody, "Assessed product", `${product.name} · ${evaluation.product_version} · ${product.id}`);
    info(reportBody, "Product revision", String(report.product_revision)); info(reportBody, "Pinned rule pack", `${evaluation.pack_id} · ${evaluation.pack_version}`);
    info(reportBody, "Definition fingerprint", evaluation.pack_sha256); info(reportBody, "Evaluated at", stamp(evaluation.evaluated_at));
    info(reportBody, "Refresh due", stamp(report.next_refresh_at || evaluation.reevaluate_at)); info(reportBody, "Assessment engine", evaluation.engine_version);
    info(reportBody, "Publisher review status", evaluation.pack_review_status === "reviewed" ? t("Reviewed (publisher declaration)") : t("Draft pack"));
    info(reportBody, "Runtime sample limit", String(report.sample_limit));
    const totals = node("div", undefined, "plugin-assessment-totals"); totals.id = "plugin-assessment-totals";
    for (const [status, amount] of Object.entries(summarizeControls(evaluation.controls))) totals.append(node("div", `${t(controlStates[status])}: ${amount} / ${evaluation.controls.length}`));
    reportBody.append(totals, message("p", "Unknown is not pass. Not applicable is not pass. References describe recorded evidence, not independent verification. Legal compliance remains undetermined.", "field-hint"));
    if (!ready) reportBody.append(message("p", "No control results were returned. Do not infer that requirements are satisfied.", "field-hint"));
    const selection = filter.value || "all";
    filter.replaceChildren(...Object.entries(filters).map(([value, title]) => { const option = node("option", t(title)); option.value = value; return option; })); filter.value = selection;
    renderControls();
  }
  renderPack(); renderReport();
  return {
    sync(next) {
      const nextPackIdentity = next.pack ? JSON.stringify([next.pack.id, next.pack.version, next.pack.sha256]) : "";
      const nextProductIdentity = next.product ? JSON.stringify([next.product.id, next.product.revision]) : "";
      const changed = dirty !== next.dirty || productIdentity !== nextProductIdentity || packIdentity !== nextPackIdentity;
      product = next.product; dirty = next.dirty; descriptor = next.pack;
      if (changed) { report = null; reportMessage = ""; }
      if (packIdentity !== nextPackIdentity) {
        packToken++; loading = false; definition = null; packError = false; packIdentity = nextPackIdentity; renderPack();
        if (packPanel.open) loadPack();
      }
      if (productIdentity !== nextProductIdentity) { search.value = ""; filter.value = "all"; }
      productIdentity = nextProductIdentity;
      if (changed) renderReport();
    },
    showReport(value) {
      reportMessage = "";
      if (dirty || !assessmentMatches(value, product, descriptor)) {
        report = null; reportMessage = "Assessment version mismatch. Reload configuration and evaluate the saved product again."; renderReport(); return false;
      }
      report = value; renderReport(); return true;
    },
    invalidate(key = "Load the latest assessment or evaluate the saved product.") { report = null; reportMessage = key; renderReport(); },
    relocalize() { renderPack(); renderReport(); },
    reset() {
      packToken++; loading = false; packError = false; descriptor = product = definition = report = null; dirty = false;
      packIdentity = productIdentity = reportMessage = ""; search.value = ""; filter.value = "all"; packPanel.open = false; renderPack(); renderReport();
    },
  };
}
