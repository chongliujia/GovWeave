import { t, formatDateTime } from "/i18n.js";

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
}

export function createPluginCoverage({ request, container }) {
  let product = null, dirty = false, identity = "", generation = 0, busy = false, report = null, failed = false;
  const panel = node("details", undefined, "plugin-disclosure"); panel.id = "plugin-coverage-panel";
  const title = node("summary"), hint = node("p", undefined, "plugin-boundary");
  const reload = node("button", undefined, "secondary"); reload.type = "button"; reload.id = "plugin-coverage-load";
  const status = node("p", undefined, "field-hint"); status.id = "plugin-coverage-status"; status.setAttribute("role", "status");
  const body = node("div", undefined, "plugin-coverage-routes"); body.id = "plugin-coverage-body";
  panel.append(title, hint, reload, status, body); container.append(panel);

  function render() {
    title.textContent = t("System traffic coverage");
    hint.textContent = t("Only gateway-observed calls are shown. Configuration, trace headers and successful probes do not prove that all application, RAG or agent traffic traverses this gateway.");
    reload.textContent = t("Refresh coverage snapshot"); reload.disabled = !product || dirty || busy;
    status.textContent = !product || dirty ? t("Save and select a product before inspecting coverage.") : busy ? t("Loading coverage…") : failed ? t("Coverage unavailable. Retry without changing configuration.") : !report ? t("Load the current instance's coverage snapshot.") : t("Snapshot: {time} · {count}/{limit} global recent records · older history may be missing", { time: formatDateTime(report.observed_at), count: report.global_sample_size, limit: report.sample_limit });
    body.replaceChildren();
    if (!report) return;
    const gaps = node("section", undefined, "plugin-boundary");
    gaps.append(node("strong", t("Whole-system coverage: not established")));
    const labels = {
      application_ingress_egress: t("Application user-input and final-output boundary"),
      agent_handoffs: t("Internal agent handoffs, queues and memory"),
      retrieval_outside_gateway: t("Retrieval or vector-store access outside governed read tools"),
      direct_provider_egress: t("Direct provider calls and network bypass paths"),
    };
    const list = node("ul");
    for (const channel of report.unverified_channels) list.append(node("li", labels[channel] || channel));
    gaps.append(list, node("p", t("These paths require separate integration and network enforcement evidence. This view never marks them covered from model or tool call counts.")));
    body.append(gaps);
    if (!report.snapshot.audit_available) body.append(node("p", t("Audit unavailable: counts are unknown, not zero."), "plugin-boundary"));
    if (!report.routes.length) body.append(node("p", t("No configured or observed routes in this product scope.")));
    const states = {
      configured: t("Configured; not proof of traffic coverage"), disabled: t("Disabled"), revoked: t("Revoked"), unresolved: t("Unresolved or historical route; no current grant inferred"),
      observed: t("Runtime request observed"), not_observed: t("No runtime request in this sample"), unavailable: t("Unavailable"),
    };
    const operations = { "chat.completions": t("Model calls"), "tools.invoke": t("Governed read-tool calls"), "content.evaluate": t("Standalone content checks (not automatic enforcement)") };
    const modes = { disabled: t("Disabled"), observe: t("Observe"), block: t("Block"), redact: t("Redact"), out_of_scope: t("Outside policy scope") };
    for (const route of report.routes) {
      const card = node("section", undefined, "plugin-coverage-route");
      card.append(node("h5", `${operations[route.operation] || route.operation}${route.alias ? ` · ${route.alias}` : ""}`));
      card.append(node("code", `${route.application_id}${route.target_id ? ` / ${route.target_id}` : ""}`));
      card.append(node("p", `${states[route.configuration]} · ${states[route.observation]}`));
      if (route.credential_input_mode) card.append(node("p", t("Current credential-input policy: {mode}", { mode: modes[route.credential_input_mode] || route.credential_input_mode })));
      if (route.sensitive_output_mode) card.append(node("p", t("Current sensitive-output policy: {mode}", { mode: modes[route.sensitive_output_mode] || route.sensitive_output_mode })));
      if (route.runtime) {
        card.append(node("p", t("Runtime: {requests} requests · {finished} finished · {unfinished} unfinished · {blocked} blocked · {failed} failed", route.runtime)));
        card.append(node("p", t("Upstream attempted: {attempted} · Traced requests: {traced}", { attempted: route.runtime.upstream_attempted, traced: route.runtime.traced })));
        card.append(node("p", t("Synthetic probes (separate): {requests}", route.probes)));
        if (route.runtime.last_observed_at) card.append(node("p", t("Last runtime observation: {time}", { time: formatDateTime(route.runtime.last_observed_at) })));
        if (route.runtime.last_trace_id) card.append(node("code", `Trace ID: ${route.runtime.last_trace_id}`));
      }
      body.append(card);
    }
    body.append(node("p", t("Policy modes describe current configuration, not historical decisions. A request may be blocked before any upstream call. Content checks do not redact returned text or prove that the caller enforced the result."), "field-hint"));
  }

  reload.addEventListener("click", async () => {
    if (!product || dirty || busy) return;
    const token = ++generation, selected = product;
    busy = true; failed = false; report = null; render();
    try {
      const next = await request(`/api/v1/compliance/products/${encodeURIComponent(selected.id)}/coverage`);
      if (token !== generation) return;
      if (next.product_id !== selected.id || next.snapshot.product_revision !== selected.revision) throw new Error("Coverage identity mismatch");
      report = next;
    } catch {
      if (token === generation) failed = true;
    } finally {
      if (token === generation) { busy = false; render(); }
    }
  });

  render();
  return {
    sync(next) {
      const key = JSON.stringify([next.product?.id, next.product?.revision, next.dirty, next.resources?.revision, next.policyRevision]);
      product = next.product; dirty = next.dirty;
      if (key !== identity) { generation++; identity = key; busy = failed = false; report = null; }
      render();
    },
    relocalize: render,
    reset() { this.sync({ product: null, dirty: false }); panel.open = false; },
  };
}
