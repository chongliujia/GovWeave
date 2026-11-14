import { t, formatDateTime } from "/i18n.js";
import { createPluginAssessment } from "/plugin-assessment.js";
import { createPluginTests } from "/plugin-tests.js";
import { createPluginCoverage } from "/plugin-coverage.js";

const el = id => document.getElementById(id);
const node = (tag, text, className) => {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
};
const label = (tag, key, className) => {
  const element = node(tag, t(key), className);
  element.dataset.pluginLabel = key;
  return element;
};
const modes = { disabled: "Disabled", observe: "Observe", block: "Block", redact: "Redact and recheck" };
const modeHints = { disabled: "Do not apply sensitive-output protection.", observe: "Record findings and return the original output.", block: "Withhold output when selected categories match.", redact: "Replace matched content, then verify before returning." };
const detectorNames = { "sensitive-text-v1": "Pattern matching", "sensitive-text-v2": "Normalized text", "sensitive-text-v3": "Formatted and encoded text" };
const categories = { credential: "Credentials", email: "Email addresses", phone: "Mainland China mobile numbers" };
const reviews = { draft: "Draft pack", reviewed: "Reviewed (publisher declaration)" };
const frameworks = { internal_policy: "Internal policy", law: "Law", regulation: "Regulation", standard: "Standard", voluntary_framework: "Voluntary framework" };
const assessments = { gaps_detected: "Control gaps detected", insufficient_evidence: "Insufficient evidence", satisfied: "Technical checks satisfied", not_applicable: "Not applicable", pending: "Assessment pending", error: "Assessment unavailable" };
const previewResults = { disabled: "Protection disabled: no scan; original text returned.", allow: "No non-exempt selected matches: original text returned.", observe: "Selected matches observed: original text returned.", block: "Selected matches blocked: output withheld.", redacted: "Text redacted and rechecked.", error: "Check incomplete or failed: output withheld." };
const previewReasons = { policy_disabled: "Protection is disabled.", patterns_not_observed: "Configured patterns were not observed.", patterns_observed: "Configured patterns were observed.", finding_limit: "Finding limit exceeded; the result is not a clean scan.", encoding_limit: "Encoding limit exceeded; the result is not a clean scan.", redaction_unavailable: "Redaction or its recheck could not complete." };
const packKey = pack => JSON.stringify([pack.id, pack.version]);

export function createPluginConsole({ request, notice }) {
  const root = el("page-plugins");
  let data = null, product = null, busy = false, epoch = 0;
  let productBaseline = "", outputBaseline = "", activeTab = "output";
  let outputTarget = "";
  let preview = null, previewSignature = "", previewMessage = "";
  const header = node("div", undefined, "section-title");
  const reload = label("button", "Reload plugin configuration", "secondary");
  reload.type = "button"; reload.id = "plugins-reload";
  header.append(label("h2", "Installed plugins"), reload);
  const status = node("p", undefined, "field-hint"); status.id = "plugins-status"; status.setAttribute("role", "status");
  root.append(header, status);
  const tabs = node("div", undefined, "plugin-tabs"); tabs.setAttribute("role", "tablist"); tabs.setAttribute("aria-label", t("Plugin categories")); root.append(tabs);
  const grid = node("div", undefined, "plugin-grid"); root.append(grid);

  function section(title, id) {
    const card = node("section", undefined, "plugin-card");
    const heading = label("h3", title); heading.id = `${id}-heading`; card.setAttribute("aria-labelledby", heading.id);
    const form = node("form"); form.id = `${id}-form`;
    const fields = node("fieldset"); fields.id = `${id}-fields`; fields.disabled = true;
    card.append(heading, form); form.append(fields); grid.append(card);
    return { card, form, fields };
  }
  function field(parent, title, id, tag = "input") {
    const wrapper = node("label", undefined, "plugin-field"), control = node(tag);
    control.id = id; wrapper.append(label("span", title), control); parent.append(wrapper);
    return control;
  }
  function button(parent, title, id, type = "submit") {
    const control = label("button", title, type === "submit" ? "primary" : "secondary"); control.id = id; control.type = type; parent.append(control); return control;
  }
  function selectOptions(control, entries, value) {
    control.replaceChildren(...entries.map(([id, name]) => {
      const option = node("option", name); option.value = id; return option;
    }));
    control.value = value;
  }
  function selected(id) { return [...el(id).querySelectorAll("input:checked")].map(input => input.value); }
  function checks(parent, title, id) {
    const group = node("fieldset", undefined, "plugin-checks"); group.id = id; group.append(label("legend", title)); parent.append(group); return group;
  }
  function renderChecks(id, items, chosen) {
    const group = el(id), legend = group.firstElementChild;
    group.replaceChildren(legend);
    const available = new Set(items.map(item => item[0]));
    for (const missing of chosen.filter(value => !available.has(value))) items.push([missing, `${missing} · ${t("Unavailable")}`]);
    for (const [value, text] of items) {
      const wrapper = node("label", undefined, "check-line"), input = node("input");
      input.type = "checkbox"; input.value = value; input.checked = chosen.includes(value);
      wrapper.append(input, node("span", text)); group.append(wrapper);
    }
  }

  const compliance = section("Compliance frameworks / rule packs", "plugin-product");
  const productSelect = field(compliance.fields, "Product", "plugin-product-select", "select");
  const name = field(compliance.fields, "Product name", "plugin-product-name"); name.required = true; name.maxLength = 100;
  const version = field(compliance.fields, "Product version", "plugin-product-version"); version.required = true; version.maxLength = 100;
  checks(compliance.fields, "Product applications", "plugin-product-apps");
  const packs = field(compliance.fields, "Installed rule pack version", "plugin-pack", "select"); packs.required = true;
  const packDetail = node("p", undefined, "plugin-detail"); packDetail.id = "plugin-pack-detail";
  compliance.fields.append(packDetail, label("p", "One pinned rule pack per product. Existing profile facts are preserved; new products start without declared evidence. Missing evidence is not a pass.", "field-hint"));
  button(compliance.fields, "Save product and rule pack", "plugin-product-save");
  const evaluate = button(compliance.fields, "Evaluate saved product", "plugin-evaluate", "button");
  const latestAssessment = button(compliance.fields, "Load latest assessment", "plugin-assessment-latest", "button");
  const result = node("p", undefined, "plugin-detail"); result.id = "plugin-evaluation"; result.setAttribute("role", "status"); compliance.card.append(result);

  const output = section("Sensitive-output detector / redaction", "plugin-output");
  const target = field(output.fields, "Policy target", "plugin-output-target", "select");
  const inherit = button(output.fields, "Use default policy", "plugin-output-inherit", "button");
  const targetHint = node("p", undefined, "field-hint"); targetHint.id = "plugin-output-target-hint";
  const detectors = field(output.fields, "Detector version", "plugin-detector", "select");
  const detectorDetail = node("p", undefined, "plugin-detail"); detectorDetail.id = "plugin-detector-detail"; output.fields.append(detectorDetail);
  const mode = field(output.fields, "Processing mode", "plugin-mode", "select");
  checks(output.fields, "Detection categories", "plugin-categories");
  const scope = field(output.fields, "Application scope", "plugin-scope", "select");
  checks(output.fields, "Protected applications", "plugin-output-apps");
  const emails = field(output.fields, "Exact public email exceptions (one per line)", "plugin-public-emails", "textarea"); emails.rows = 3; emails.maxLength = 4096;
  output.fields.append(label("p", "Exceptions are exact addresses, not domains or wildcards. They do not exempt credentials or other controls.", "field-hint"));
  output.fields.append(label("p", "Applies to non-streaming model responses and tool outputs. Protected streaming requests are rejected. Incomplete or failed protected checks withhold output, including observe mode. Observe returns original content only after a completed check. Standalone content evaluation does not redact text.", "plugin-boundary"));
  button(output.fields, "Save detector policy", "plugin-output-save");
  const outputSaved = node("p", undefined, "plugin-detail"); outputSaved.id = "plugin-output-saved"; output.card.append(outputSaved);
  const historyButton = button(output.card, "Show detector policy history", "plugin-history-load", "button"); historyButton.disabled = true;
  const history = node("ol", undefined, "plugin-history"); history.id = "plugin-history"; output.card.append(history);

  function step(title, description) {
    const container = node("section", undefined, "plugin-step");
    container.append(label("h4", title));
    if (description) container.append(label("p", description, "field-hint"));
    return container;
  }
  function disclosure(title, id) {
    const container = node("details", undefined, "plugin-disclosure"); container.id = id;
    container.append(label("summary", title)); return container;
  }
  function choiceCards(control, title, id, searchable = false) {
    control.parentElement.hidden = true;
    const container = node("fieldset", undefined, "plugin-choices"); container.id = id;
    container.append(label("legend", title));
    const toolbar = node("div", undefined, "plugin-catalog-toolbar");
    const search = searchable ? field(toolbar, "Search rule packs", "plugin-pack-search") : null;
    if (search) search.type = "search";
    const filter = searchable ? field(toolbar, "Framework type", "plugin-pack-filter", "select") : null;
    if (searchable) container.append(toolbar);
    const list = node("div", undefined, "plugin-choice-list"); container.append(list);
    const empty = label("p", "No matching plugins. Change the search or filter.", "plugin-empty"); empty.hidden = true; container.append(empty);
    function filterItems() {
      let visible = 0;
      for (const item of list.children) {
        item.hidden = !!search && (!item.dataset.search.includes(search.value.trim().toLowerCase()) || filter.value && item.dataset.framework !== filter.value);
        if (!item.hidden) visible++;
      }
      empty.hidden = visible > 0;
      empty.textContent = !list.children.length && searchable ? t("No selectable installed rule pack. Install validated JSON packs in the data directory's rule-packs folder and restart the service. Reload after installation.") : t("No matching plugins. Change the search or filter.");
    }
    search?.addEventListener("input", filterItems); filter?.addEventListener("change", filterItems);
    return {
      container,
      render(items) {
        if (filter) selectOptions(filter, [["", t("All framework types")], ...Object.entries(frameworks).map(([value, text]) => [value, t(text)])], filter.value);
        if (search) search.disabled = !items.length;
        if (filter) filter.disabled = !items.length;
        list.replaceChildren(...items.map(item => {
          const card = node("label", undefined, "plugin-choice"), radio = node("input");
          radio.type = "radio"; radio.name = `${id}-choice`; radio.value = item.value;
          const content = node("span", undefined, "plugin-choice-content"), heading = node("span", undefined, "plugin-choice-heading");
          heading.append(node("strong", item.title));
          const saved = node("span", t("Saved configuration"), "plugin-saved-badge"); saved.dataset.savedBadge = ""; heading.append(saved);
          content.append(heading);
          if (item.version) content.append(node("code", item.version));
          if (item.description) content.append(node("span", item.description, "plugin-choice-description"));
          if (item.meta) content.append(node("span", item.meta, "plugin-choice-meta"));
          card.dataset.search = [item.title, item.version, item.description, item.meta, item.value].join(" ").toLowerCase();
          card.dataset.framework = item.framework || "";
          radio.addEventListener("change", () => {
            if (!radio.checked) return;
            control.value = radio.value; control.dispatchEvent(new Event("change", { bubbles: true }));
          });
          radio.addEventListener("input", () => { control.value = radio.value; });
          card.append(radio, content); return card;
        }));
        filterItems();
      },
      sync(savedValue) {
        for (const card of list.children) {
          const radio = card.querySelector("input"); radio.checked = radio.value === control.value;
          card.classList.toggle("is-selected", radio.checked);
          card.querySelector("[data-saved-badge]").hidden = radio.value !== savedValue;
        }
      },
      reset() { if (search) search.value = ""; if (filter) filter.value = ""; list.replaceChildren(); empty.hidden = true; },
    };
  }
  function applicationPicker(id) {
    const group = el(id), container = node("div", undefined, "plugin-application-picker");
    group.before(container); container.append(group);
    const toolbar = node("div", undefined, "plugin-application-toolbar");
    const search = field(toolbar, "Search applications", `${id}-search`); search.type = "search";
    const actions = node("div", undefined, "plugin-selection-actions");
    const selectVisible = button(actions, "Select visible", `${id}-select-visible`, "button");
    const clearVisible = button(actions, "Clear visible", `${id}-clear-visible`, "button");
    toolbar.append(actions); container.prepend(toolbar);
    const count = node("p", undefined, "plugin-selection-count"); count.id = `${id}-count`; count.setAttribute("role", "status");
    const empty = label("p", "No matching applications.", "plugin-empty"); empty.hidden = true;
    container.append(count, empty);
    function refresh() {
      const options = [...group.querySelectorAll("label")];
      for (const option of options) option.hidden = !`${option.textContent} ${option.querySelector("input").value}`.toLowerCase().includes(search.value.trim().toLowerCase());
      empty.hidden = options.some(option => !option.hidden);
      count.textContent = t("{selected} selected · {total} applications", { selected: selected(id).length, total: options.length });
      selectVisible.disabled = !options.some(option => !option.hidden && !option.querySelector("input").checked);
      clearVisible.disabled = !options.some(option => !option.hidden && option.querySelector("input").checked);
    }
    for (const [button, checked] of [[selectVisible, true], [clearVisible, false]]) button.addEventListener("click", () => {
      for (const option of group.querySelectorAll("label")) if (!option.hidden) option.querySelector("input").checked = checked;
      group.dispatchEvent(new Event("change", { bubbles: true }));
    });
    search.addEventListener("input", refresh);
    return { container, refresh, reset() { search.value = ""; refresh(); } };
  }

  const packChoices = choiceCards(packs, "Choose a rule pack", "plugin-pack-choices", true);
  const detectorChoices = choiceCards(detectors, "Choose a detector version", "plugin-detector-choices");
  const modeChoices = choiceCards(mode, "Choose how to handle findings", "plugin-mode-choices");
  const productApps = applicationPicker("plugin-product-apps"), outputApps = applicationPicker("plugin-output-apps");
  const productSetup = step("Product profile", "Choose an existing product or create a new assessment scope.");
  const profileRow = node("div", undefined, "plugin-profile-row"); profileRow.append(name.parentElement, version.parentElement);
  productSetup.append(productSelect.parentElement, profileRow, productApps.container);
  const packSetup = step("Framework selection", "Choose an installed version. This does not enable runtime blocking.");
  const packProvenance = disclosure("Version details & fingerprint", "plugin-pack-provenance"); packProvenance.append(packDetail);
  packSetup.append(packs.parentElement, packChoices.container, packProvenance);
  const productNotes = disclosure("Assessment limits", "plugin-product-notes");
  productNotes.append(compliance.fields.querySelector(".field-hint"));
  const productColumns = node("div", undefined, "plugin-workspace"); productColumns.append(packSetup, productSetup);
  const productSave = el("plugin-product-save");
  compliance.fields.append(productColumns, productNotes);

  const detectorSetup = step("Detector selection", "Compare version coverage. Selection alone does not change the live policy.");
  detectorSetup.append(detectors.parentElement, detectorChoices.container, detectorDetail);
  const outputSetup = step("Runtime configuration", "Configure the default policy or select one application for independent settings.");
  outputSetup.append(mode.parentElement, modeChoices.container, el("plugin-categories"), scope.parentElement, outputApps.container);
  const scopeHint = label("p", "All applications includes applications created later.", "plugin-scope-warning"); outputSetup.append(scopeHint);
  const advanced = disclosure("Advanced: public email exceptions", "plugin-output-advanced");
  advanced.append(emails.parentElement, output.fields.querySelector(".field-hint")); outputSetup.append(advanced);
  const outputNotes = disclosure("Processing limits & safety", "plugin-output-notes"); outputNotes.append(output.fields.querySelector(".plugin-boundary"));
  const historyPanel = disclosure("Policy revision history", "plugin-history-panel"); historyPanel.append(historyButton, history);
  const outputColumns = node("div", undefined, "plugin-workspace"); outputColumns.append(detectorSetup, outputSetup);
  const outputSave = el("plugin-output-save");
  outputSaved.classList.add("plugin-current-policy"); output.fields.append(target.parentElement, targetHint, inherit, outputSaved, outputColumns, outputNotes, historyPanel);
  el("plugin-categories").classList.add("plugin-category-chips");

  const previewPanel = disclosure("Try before saving", "plugin-preview-panel");
  const previewHelp = label("p", "Test the current draft as if this text were in scope. This does not check application routing, call a model, save policy changes or create evidence. Use synthetic text; samples and results are not stored by GovWeave.", "field-hint");
  previewPanel.append(previewHelp);
  const previewGrid = node("div", undefined, "plugin-preview-grid"), previewInput = node("div", undefined, "plugin-preview-input");
  const sampleActions = node("div", undefined, "plugin-selection-actions");
  const emailSample = button(sampleActions, "Email sample", "plugin-preview-email", "button");
  const encodedSample = button(sampleActions, "Encoded sample", "plugin-preview-encoded", "button");
  const credentialSample = button(sampleActions, "Credential sample", "plugin-preview-credential", "button");
  previewInput.append(sampleActions);
  const sample = field(previewInput, "Sample text", "plugin-preview-text", "textarea");
  sample.rows = 6; sample.maxLength = 8192; sample.autocomplete = "off"; sample.spellcheck = false;
  const byteCount = node("p", undefined, "field-hint"); byteCount.id = "plugin-preview-bytes"; sample.setAttribute("aria-describedby", byteCount.id); previewInput.append(byteCount);
  const previewActions = node("div", undefined, "plugin-selection-actions");
  const previewRun = button(previewActions, "Test current draft", "plugin-preview-run", "button");
  const previewClear = button(previewActions, "Clear sample and result", "plugin-preview-clear", "button"); previewInput.append(previewActions);
  const previewDisplay = node("div", undefined, "plugin-preview-result"); previewDisplay.id = "plugin-preview-result"; previewDisplay.hidden = true;
  const previewStatus = node("p", undefined, "field-hint"); previewStatus.id = "plugin-preview-status"; previewStatus.setAttribute("role", "status");
  previewGrid.append(previewInput, previewDisplay); previewPanel.append(previewGrid, previewStatus);
  output.fields.insertBefore(previewPanel, outputNotes);
  const previewOpen = button(detectorSetup, "Try before saving", "plugin-preview-open", "button");
  previewOpen.addEventListener("click", () => { previewPanel.open = true; sample.focus(); });
  for (const [control, text] of [[emailSample, "Contact private@example.test"], [encodedSample, "Encoded: cHJpdmF0ZUBleGFtcGxlLnRlc3Q="], [credentialSample, "Synthetic example: -----BEGIN PRIVATE KEY-----"]]) control.addEventListener("click", () => {
    sample.value = text; renderPreview(); sample.focus();
  });
  previewClear.addEventListener("click", () => { sample.value = ""; clearPreview(); renderPreview(); });

  function savebar(fields, save, id) {
    const bar = node("div", undefined, "plugin-savebar"), text = node("div", undefined, "plugin-save-summary");
    const state = node("strong"), summary = node("span"); state.id = `${id}-dirty`; summary.id = `${id}-summary`;
    state.setAttribute("role", "status"); text.append(state, summary);
    const actions = node("div", undefined, "plugin-save-actions"), discard = button(actions, "Discard changes", `${id}-discard`, "button");
    actions.append(save); bar.append(text, actions); fields.append(bar);
    return { state, summary, discard };
  }
  const productBar = savebar(compliance.fields, productSave, "plugin-product");
  const outputBar = savebar(output.fields, outputSave, "plugin-output");
  const assessmentPanel = disclosure("Saved product assessment", "plugin-assessment-panel");
  const assessmentActions = node("div", undefined, "plugin-selection-actions"); assessmentActions.append(latestAssessment, evaluate);
  assessmentPanel.append(assessmentActions, result);
  compliance.fields.insertBefore(assessmentPanel, productBar.state.closest(".plugin-savebar"));
  const packInspection = node("div"); compliance.fields.insertBefore(packInspection, productNotes);
  const assessmentView = createPluginAssessment({ request, packContainer: packInspection, reportContainer: assessmentPanel });
  const testsView = createPluginTests({ request, container: compliance.card });
  const coverageView = createPluginCoverage({ request, container: compliance.card });
  const tabEntries = [["output", output, "Detectors & redaction"], ["product", compliance, "Frameworks & rule packs"]];
  for (const [key, panel, title] of tabEntries) {
    const tab = label("button", title, "plugin-tab"); tab.type = "button"; tab.id = `plugin-tab-${key}`;
    tab.setAttribute("role", "tab"); panel.card.id = `plugin-panel-${key}`;
    tab.setAttribute("aria-controls", panel.card.id); panel.card.setAttribute("role", "tabpanel"); panel.card.setAttribute("aria-labelledby", tab.id);
    tab.addEventListener("click", () => showTab(key));
    tab.addEventListener("keydown", event => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault(); const next = event.key === "Home" ? "output" : event.key === "End" ? "product" : key === "output" ? "product" : "output";
      showTab(next); el(`plugin-tab-${next}`).focus();
    });
    tabs.append(tab);
  }
  function showTab(key) {
    activeTab = key;
    for (const [value, panel] of tabEntries) {
      const tab = el(`plugin-tab-${value}`), active = value === key;
      panel.card.hidden = !active; tab.setAttribute("aria-selected", String(active)); tab.tabIndex = active ? 0 : -1;
    }
  }
  showTab(activeTab);

  function productSignature() { return JSON.stringify([name.value, version.value, packs.value, selected("plugin-product-apps").sort()]); }
  function outputSignature() { return JSON.stringify([detectors.value, mode.value, scope.value, scope.value === "all" ? [] : selected("plugin-output-apps").sort(), selected("plugin-categories").sort(), emails.value]); }
  function productDirty() { return !!data && productSignature() !== productBaseline; }
  function outputDirty() { return !!data && outputSignature() !== outputBaseline; }
  function previewInputBody() { return { text: sample.value, detector_version: detectors.value, mode: mode.value, categories: selected("plugin-categories"), public_emails: emails.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean) }; }
  function currentPreviewSignature() { return JSON.stringify([outputSignature(), sample.value]); }
  function clearPreview() { preview = null; previewSignature = ""; previewMessage = ""; previewDisplay.replaceChildren(); previewDisplay.hidden = true; previewStatus.textContent = ""; }
  function renderPreview() {
    if (previewSignature && previewSignature !== currentPreviewSignature()) {
      clearPreview(); previewMessage = "The sample or draft changed. Run the preview again.";
    }
    const bytes = new TextEncoder().encode(sample.value).length;
    const maximum = data?.catalog.detectors.find(item => item.version === detectors.value)?.max_bytes || 8192;
    const requestTooLarge = new TextEncoder().encode(JSON.stringify(previewInputBody())).length > 16384;
    byteCount.textContent = t("{bytes} / {maximum} UTF-8 bytes", { bytes, maximum });
    if (bytes > maximum) byteCount.textContent += ` · ${t("Sample exceeds the detector input limit.")}`;
    if (requestTooLarge) byteCount.textContent += ` · ${t("Preview JSON request must not exceed 16 KiB.")}`;
    previewRun.disabled = !data || !sample.value.trim() || bytes > maximum || requestTooLarge || !detectors.value || !selected("plugin-categories").length;
    previewClear.disabled = !sample.value && !preview && !previewMessage;
    previewStatus.textContent = previewMessage ? t(previewMessage) : "";
    previewDisplay.hidden = !preview;
    if (!preview) return;
    const outcome = node("strong", t(previewResults[preview.result] || "Preview unavailable.")); outcome.id = "plugin-preview-outcome";
    const meta = node("p", t("Detector: {version} · Mode: {mode}", { version: preview.detector_version, mode: t(modes[preview.mode]) }), "field-hint");
    const matches = node("p", t("Matched categories: {categories}", { categories: preview.matched_categories.map(value => t(categories[value] || value)).join(", ") || t("No selected matches") }), "field-hint");
    previewDisplay.replaceChildren(label("h4", "Preview only — not saved evidence"), outcome, meta, matches);
    if (preview.matched_rules.length) previewDisplay.append(node("p", t("Rule IDs: {rules}", { rules: preview.matched_rules.join(", ") }), "field-hint"));
    previewDisplay.append(node("p", t("Public email exceptions applied: {count}", { count: preview.public_email_exceptions }), "field-hint"));
    if (previewReasons[preview.reason]) previewDisplay.append(node("p", t(previewReasons[preview.reason]), "field-hint"));
    if (preview.redaction) previewDisplay.append(node("p", preview.redaction.scope === "full_output" ? t("Entire output replaced") : t("Redaction replacements: {count}", { count: preview.redaction.replacements }), "field-hint"));
    if (typeof preview.output === "string") {
      const text = node("pre", preview.output, "plugin-preview-output"); text.id = "plugin-preview-output";
      previewDisplay.append(label("h4", "Preview output"), text);
    }
    previewDisplay.append(label("p", "A sample result is not a guarantee of complete detection or legal compliance. Model envelopes, tool arguments and application routing are outside this preview.", "field-hint"));
  }
  function renderDraft() {
    if (!data) return;
    for (const [bar, dirty] of [[productBar, productDirty()], [outputBar, outputDirty()]]) {
      bar.state.textContent = dirty ? t("Unsaved changes") : t("No unsaved changes");
      bar.state.dataset.dirty = String(dirty); bar.discard.disabled = !dirty;
    }
    const pack = data.catalog.rule_packs.find(item => packKey(item) === packs.value);
    productBar.summary.textContent = pack ? `${pack.name} · ${pack.version} · ${t("Applications selected: {count}", { count: selected("plugin-product-apps").length })}` : t("Select a rule pack and product applications to continue.");
    outputBar.summary.textContent = `${detectors.value} · ${t(modes[mode.value])} · ${target.value ? target.selectedOptions[0].textContent : scope.value === "all" ? t("All applications, including future ones") : t("Applications selected: {count}", { count: selected("plugin-output-apps").length })}`;
    productSave.disabled = !productDirty() || !pack || !name.value.trim() || !version.value.trim() || !selected("plugin-product-apps").length;
    outputSave.disabled = !outputDirty() || !detectors.value || !selected("plugin-categories").length || scope.value === "selected" && !selected("plugin-output-apps").length;
    if (productDirty() && (!name.value.trim() || !version.value.trim() || !selected("plugin-product-apps").length)) productBar.summary.textContent = t("Complete the product name, version, rule pack and application scope.");
    if (!selected("plugin-categories").length || scope.value === "selected" && !selected("plugin-output-apps").length) outputBar.summary.textContent = t("Choose at least one category and at least one application for a selected scope.");
    evaluate.disabled = !product || productDirty();
    latestAssessment.disabled = !product || productDirty();
    if (productDirty()) result.textContent = "";
  }

  function applications() { return data.resources.applications.map(app => [app.id, `${app.name}${app.revoked ? ` · ${t("Revoked")}` : ""}`]); }
  function renderDetails() {
    if (!data) return;
    const pack = data.catalog.rule_packs.find(item => packKey(item) === packs.value);
    packDetail.textContent = pack ? `${pack.name} · ${t(frameworks[pack.framework_kind] || pack.framework_kind)} · ${t(reviews[pack.review_status] || pack.review_status)} · ${t("Controls: {count}", { count: pack.control_count })}\nSHA-256: ${pack.sha256}` : t("No selectable installed rule pack. Install validated JSON packs in the data directory's rule-packs folder and restart the service. Reload after installation.");
    if (!pack && data.catalog.rule_packs.length) packDetail.textContent = packs.value ? t("Saved rule pack is not installed") : t("Select an installed rule pack to inspect its version and review status.");
    const detector = data.catalog.detectors.find(item => item.version === detectors.value);
    detectorDetail.textContent = detector ? t("Local compiled plugin · Up to {bytes} bytes / {count} findings. No remote content transfer.", { bytes: detector.max_bytes, count: detector.max_findings }) : t("Unavailable");
    scope.parentElement.hidden = !!target.value;
    inherit.hidden = !target.value;
    inherit.disabled = outputDirty() || !(data.policy.application_policies || []).some(p => p.application_id === target.value);
    targetHint.textContent = target.value ? (savedOutput().source === "application" ? t("This application uses independent settings.") : t("This application inherits the default policy. Saving creates independent settings.")) : t("Default settings apply to applications without an independent policy. Independent policies: {count}", { count: (data.policy.application_policies || []).length });
    el("plugin-output-apps").hidden = !!target.value || scope.value !== "selected";
    el("plugin-output-apps").disabled = scope.value !== "selected";
    outputApps.container.hidden = !!target.value || scope.value !== "selected"; scopeHint.hidden = !!target.value || scope.value !== "all";
    packChoices.sync(product ? packKey({ id: product.pack_id, version: product.pack_version }) : "");
    const effective = savedOutput();
    detectorChoices.sync(effective.detector_version); modeChoices.sync(effective.mode);
    productApps.refresh(); outputApps.refresh(); renderDraft(); renderPreview();
    assessmentView.sync({ pack, product, dirty: productDirty() });
    testsView.sync({ product, resources: data.resources, dirty: productDirty() });
    coverageView.sync({ product, resources: data.resources, dirty: productDirty(), policyRevision: data.policy.revision });
    outputSaved.textContent = t("Saved detector: {version} · Revision {revision} · {mode}", { version: effective.detector_version, revision: data.policy.revision, mode: t(modes[effective.mode]) });
  }
  function renderOptions() {
    if (!data) return;
    selectOptions(target, [["", t("Default policy")], ...applications()], target.value);
    const productValue = productSelect.value, packValue = packs.value, detectorValue = detectors.value, modeValue = mode.value, scopeValue = scope.value;
    selectOptions(productSelect, [["", t("New product")], ...data.products.map(item => [item.id, `${item.name} · ${item.version}`])], productValue);
    const packEntries = [["", t("Select an installed rule pack")], ...data.catalog.rule_packs.map(item => [packKey(item), `${item.name} · ${item.version} · ${t(reviews[item.review_status] || item.review_status)}`])];
    if (packValue && !packEntries.some(item => item[0] === packValue)) packEntries.push([packValue, t("Saved rule pack is not installed")]);
    selectOptions(packs, packEntries, packValue);
    selectOptions(detectors, data.catalog.detectors.map(item => [item.version, `${t(item.name)} · ${item.version}`]), detectorValue);
    selectOptions(mode, Object.entries(modes).map(([value, text]) => [value, t(text)]), modeValue);
    selectOptions(scope, [["all", t("All applications, including future ones")], ["selected", t("Selected applications only")]], scopeValue);
    renderChecks("plugin-product-apps", applications(), selected("plugin-product-apps"));
    renderChecks("plugin-output-apps", applications(), selected("plugin-output-apps"));
    renderChecks("plugin-categories", Object.entries(categories).map(([value, text]) => [value, t(text)]), selected("plugin-categories"));
    packChoices.render(data.catalog.rule_packs.map(item => ({ value: packKey(item), title: item.name, version: item.version, framework: item.framework_kind, description: item.id, meta: `${t(frameworks[item.framework_kind] || item.framework_kind)} · ${t(reviews[item.review_status] || item.review_status)} · ${t("Controls: {count}", { count: item.control_count })}` })));
    detectorChoices.render(data.catalog.detectors.map(item => ({ value: item.version, title: t(detectorNames[item.version] || item.name), version: item.version, description: t(item.description) })));
    modeChoices.render(Object.entries(modes).map(([value, title]) => ({ value, title: t(title), description: t(modeHints[value]) })));
    renderDetails();
  }
  function restoreProduct(id) {
    product = data.products.find(item => item.id === id) || null;
    productSelect.value = product?.id || "";
    name.value = product?.name || ""; version.value = product?.version || "1.0.0";
    const value = product ? packKey({ id: product.pack_id, version: product.pack_version }) : "";
    if (value && ![...packs.options].some(option => option.value === value)) {
      const option = node("option", t("Saved rule pack is not installed")); option.value = value; packs.append(option);
    }
    packs.value = value;
    renderChecks("plugin-product-apps", applications(), product?.application_ids || []);
    productBaseline = productSignature(); result.textContent = ""; renderDetails();
  }
  function savedOutput() {
    const policy = data.policy;
    if (!target.value) return policy;
    const override = (policy.application_policies || []).find(item => item.application_id === target.value);
    const applies = !policy.application_ids.length || policy.application_ids.includes(target.value);
    return { ...(override || policy), source: override ? "application" : "default", application_ids: [target.value], mode: override?.mode || (applies ? policy.mode : "disabled") };
  }
  function restoreOutput() {
    outputTarget = target.value;
    const policy = savedOutput();
    detectors.value = policy.detector_version; mode.value = policy.mode; scope.value = policy.application_ids.length ? "selected" : "all";
    renderChecks("plugin-output-apps", applications(), policy.application_ids);
    renderChecks("plugin-categories", Object.entries(categories).map(([value, text]) => [value, t(text)]), policy.categories);
    emails.value = (policy.public_emails || []).join("\n"); outputBaseline = outputSignature(); renderDetails();
  }
  function setBusy(value) {
    busy = value; reload.disabled = value;
    compliance.fields.disabled = output.fields.disabled = value || !data;
    historyButton.disabled = value || !data;
    root.setAttribute("aria-busy", String(value));
  }
  async function run(operation) {
    if (busy) return;
    const token = epoch; setBusy(true);
    try { await operation(token); }
    catch (error) { if (token === epoch) notice(error.message, true); }
    finally { if (token === epoch) setBusy(false); }
  }
  async function load() {
    await run(async token => {
      assessmentView.invalidate(); result.textContent = "";
      status.textContent = t("Loading plugin configuration…");
      try {
        const [catalog, products, resources, policy] = await Promise.all([
          request("/api/v1/plugins"), request("/api/v1/compliance/products"), request("/api/v1/gateway"), request("/api/v1/policies/sensitive-output"),
        ]);
        if (token !== epoch) return;
        const id = product?.id;
        data = { catalog, products: products.products, resources, policy };
        renderOptions(); restoreProduct(id);
        restoreOutput(); history.replaceChildren();
        status.textContent = t("Configuration loaded. Changes take effect only after saving.");
      } catch (error) {
        if (token === epoch) status.textContent = t("Plugin configuration could not be loaded. Reload to retry; existing policies remain unchanged.");
        throw error;
      }
    });
  }
  const send = (path, body, method) => request(path, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  previewRun.addEventListener("click", () => run(async token => {
    clearPreview(); previewSignature = currentPreviewSignature(); previewMessage = "Testing current draft…"; renderPreview();
    const signature = previewSignature;
    try {
      const response = await send("/api/v1/plugins/sensitive-output/preview", previewInputBody(), "POST");
      if (token !== epoch || signature !== currentPreviewSignature()) return;
      preview = response; previewMessage = "Preview complete. Live policy remains unchanged."; renderPreview();
    } catch (error) {
      if (token === epoch) { previewMessage = "Preview failed. Check settings and retry."; renderPreview(); }
      throw error;
    }
  }));
  compliance.form.addEventListener("submit", event => {
    event.preventDefault();
    run(async token => {
      const pack = data.catalog.rule_packs.find(item => packKey(item) === packs.value), apps = selected("plugin-product-apps");
      if (!pack || !apps.length) throw new Error(t("Select an installed rule pack and at least one product application."));
      const saved = await send(`/api/v1/compliance/products${product ? `/${encodeURIComponent(product.id)}` : ""}`, {
        revision: product?.revision || 0, name: name.value, version: version.value,
        application_ids: apps, pack_id: pack.id, pack_version: pack.version, facts: product?.facts || {},
      }, product ? "PUT" : "POST");
      if (token !== epoch) return;
      data.products = [...data.products.filter(item => item.id !== saved.id), saved];
      renderOptions(); restoreProduct(saved.id);
      notice(t("Product rule pack saved. Runtime protection was not changed."));
    });
  });
  output.form.addEventListener("submit", event => {
    event.preventDefault();
    run(async token => {
      const apps = scope.value === "all" ? [] : selected("plugin-output-apps"), chosen = selected("plugin-categories");
      if (!chosen.length || scope.value === "selected" && !apps.length) throw new Error(t("Choose at least one category and at least one application for a selected scope."));
      const policy = await send(`/api/v1/policies/sensitive-output${target.value ? `/applications/${encodeURIComponent(target.value)}` : ""}`, {
        revision: data.policy.revision, detector_version: detectors.value, mode: mode.value, categories: chosen,
        ...(target.value ? {} : { application_ids: apps }), public_emails: emails.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean),
      }, "PUT");
      if (token !== epoch) return;
      data.policy = policy; history.replaceChildren(); restoreOutput();
      assessmentView.invalidate("Runtime settings changed. Reassess the saved product."); result.textContent = "";
      notice(t("Detector policy saved. New requests use the saved revision."));
    });
  });
  function loadAssessment(refresh) {
    return run(async token => {
      assessmentView.invalidate("Loading assessment…"); result.textContent = "";
      try {
        const path = `/api/v1/compliance/products/${encodeURIComponent(product.id)}`;
        const report = refresh ? await send(`${path}/evaluate`, {}, "POST") : await request(`${path}/evaluation`);
        if (token !== epoch || !assessmentView.showReport(report)) return;
        const state = report.evaluation?.status || report.state;
        result.textContent = t("Saved product revision {revision}: {state}. This is a technical evidence assessment, not legal certification.", { revision: report.product_revision, state: t(assessments[state] || state) });
      } catch (error) {
        if (token === epoch) assessmentView.invalidate("Assessment request failed. Retry without changing the saved product.");
        throw error;
      }
    });
  }
  evaluate.addEventListener("click", () => loadAssessment(true));
  latestAssessment.addEventListener("click", () => loadAssessment(false));
  historyButton.addEventListener("click", () => run(async token => {
    const snapshots = await request(`/api/v1/policies/sensitive-output${target.value ? `/applications/${encodeURIComponent(target.value)}` : ""}/history`);
    if (token !== epoch) return;
    history.replaceChildren(...snapshots.snapshots.map(entry => {
      const item = entry.policy || entry;
      const effectiveMode = target.value && item.application_ids.length && !item.application_ids.includes(target.value) ? "disabled" : item.mode;
      const row = node("li", `${item.revision} · ${item.detector_version} · ${t(modes[effectiveMode])} · ${item.updated_at ? formatDateTime(item.updated_at) : t("Initial default")}`);
      if (target.value) {
        const restore = label("button", "Restore for this application", "text-button"); restore.type = "button";
        restore.disabled = outputDirty();
        restore.addEventListener("click", () => run(async token => {
          if (outputDirty()) return;
          const policy = await send(`/api/v1/policies/sensitive-output/applications/${encodeURIComponent(target.value)}/restore`, { revision: data.policy.revision, from_revision: item.revision }, "POST");
          if (token !== epoch) return;
          data.policy = policy; history.replaceChildren(); restoreOutput(); assessmentView.invalidate();
          notice(t("Historical settings restored as a new application policy revision."));
        }));
        row.append(restore);
      }
      return row;
    }));
  }));
  reload.addEventListener("click", () => {
    if ((productDirty() || outputDirty()) && !window.confirm(t("Reloading will discard unsaved plugin changes. Continue?"))) return;
    load();
  });
  productSelect.addEventListener("change", () => {
    if (productDirty() && !window.confirm(t("Switching products will discard this product's unsaved changes. Continue?"))) { productSelect.value = product?.id || ""; return; }
    restoreProduct(productSelect.value);
  });
  target.addEventListener("change", () => {
    if (outputDirty() && !window.confirm(t("Switching policy targets will discard unsaved changes. Continue?"))) { target.value = outputTarget; return; }
    outputTarget = target.value; history.replaceChildren(); clearPreview(); restoreOutput();
  });
  inherit.addEventListener("click", () => run(async token => {
    const policy = await send(`/api/v1/policies/sensitive-output/applications/${encodeURIComponent(target.value)}`, { revision: data.policy.revision }, "DELETE");
    if (token !== epoch) return;
    data.policy = policy; history.replaceChildren(); restoreOutput(); assessmentView.invalidate();
    notice(t("Application now uses the default policy."));
  }));
  productBar.discard.addEventListener("click", () => restoreProduct(product?.id));
  outputBar.discard.addEventListener("click", restoreOutput);
  for (const form of [compliance.form, output.form]) for (const event of ["input", "change"]) form.addEventListener(event, renderDetails);
  window.addEventListener("beforeunload", event => { if (productDirty() || outputDirty()) { event.preventDefault(); event.returnValue = ""; } });
  function localizeLabels() {
    root.querySelectorAll("[data-plugin-label]").forEach(element => { element.textContent = t(element.dataset.pluginLabel); });
    tabs.setAttribute("aria-label", t("Plugin categories"));
  }
  return {
    enter() { localizeLabels(); assessmentView.relocalize(); testsView.relocalize(); coverageView.relocalize(); if (!data) load(); },
    relocalize() {
      localizeLabels();
      renderOptions(); assessmentView.relocalize(); testsView.relocalize(); coverageView.relocalize(); status.textContent = ""; result.textContent = ""; history.replaceChildren();
    },
    reset() {
      epoch++; outputTarget = ""; data = null; product = null; productBaseline = outputBaseline = ""; setBusy(false); showTab("output");
      compliance.form.reset(); output.form.reset();
      sample.value = ""; clearPreview(); previewPanel.open = false;
      assessmentView.reset();
      testsView.reset();
      coverageView.reset();
      for (const control of [productSelect, packs, detectors, mode, scope, target]) control.replaceChildren();
      for (const id of ["plugin-product-apps", "plugin-output-apps", "plugin-categories"]) renderChecks(id, [], []);
      for (const control of [status, result, packDetail, detectorDetail, outputSaved, history, targetHint]) control.replaceChildren();
      for (const choices of [packChoices, detectorChoices, modeChoices]) choices.reset();
      productApps.reset(); outputApps.reset();
      for (const bar of [productBar, outputBar]) { bar.state.textContent = ""; bar.summary.textContent = ""; }
    },
  };
}
