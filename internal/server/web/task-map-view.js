import { t } from "/i18n.js";
import { projectTaskMap } from "/task-map.js";

const el = id => document.getElementById(id);
const node = (tag, text, className) => {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
};
const svgNode = (tag, attributes = {}) => {
  const element = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
  return element;
};
const captureLabels = { retained: "Retained capture available", not_found: "Capture not found; reason unknown",
  unavailable: "Capture could not be verified or read", not_loaded: "Capture outside this view's read budget" };
const relationLabels = { parent: "Parent reference", link: "Linked call", retry_of: "Retry reference" };

export function createTaskMap({ inspect, openEvidence }) {
  const root = el("task-map"), viewport = el("task-map-viewport"), stage = el("task-map-stage"), canvas = el("task-map-canvas");
  const search = el("task-map-search"), filter = el("task-map-filter");
  let view = null, options = {}, zoom = 1, selected = "", projection = null;

  function size() {
    stage.style.width = `${(projection?.width || 0) * zoom}px`; stage.style.height = `${(projection?.height || 0) * zoom}px`;
    canvas.style.transform = `scale(${zoom})`;
    el("task-map-zoom-value").textContent = `${Math.round(zoom * 100)}%`;
    el("task-map-zoom-out").disabled = zoom <= 0.6; el("task-map-zoom-in").disabled = zoom >= 1.4;
  }

  function highlight() {
    const neighbors = new Set([selected]);
    for (const edge of projection?.edges || []) if (edge.from === selected || edge.to === selected) { neighbors.add(edge.from); neighbors.add(edge.to); }
    canvas.querySelectorAll("[data-map-node]").forEach(item => {
      item.classList.toggle("is-selected", item.dataset.mapNode === selected);
      item.classList.toggle("is-muted", !!selected && !neighbors.has(item.dataset.mapNode));
      item.querySelector("[data-map-inspect]")?.setAttribute("aria-pressed", String(item.dataset.mapNode === selected));
    });
    canvas.querySelectorAll("[data-map-edge]").forEach(path => {
      const edge = projection.edges[Number(path.dataset.mapEdge)];
      path.classList.toggle("is-active", !!selected && (edge.from === selected || edge.to === selected));
      path.classList.toggle("is-muted", !!selected && edge.from !== selected && edge.to !== selected);
    });
  }

  function draw() {
    canvas.replaceChildren();
    projection = projectTaskMap(view, { ...options, query: search.value, filter: filter.value });
    root.hidden = !view;
    if (!view) { size(); return; }
    if (!projection.nodes.some(item => item.id === selected)) selected = "";
    el("task-map-count").textContent = t("{matched} matching calls · {related} related calls · {references} unresolved or ambiguous spans", projection);
    el("task-map-empty").hidden = projection.nodes.length > 0;
    viewport.hidden = !projection.nodes.length;
    canvas.style.width = `${projection.width}px`; canvas.style.height = `${projection.height}px`;
    const svg = svgNode("svg", { width: projection.width, height: projection.height, "aria-hidden": "true", class: "task-map-lines" });
    const defs = svgNode("defs"), marker = svgNode("marker", { id: "task-map-arrow", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" });
    marker.append(svgNode("path", { d: "M 0 0 L 10 5 L 0 10 z", fill: "currentColor" })); defs.append(marker); svg.append(defs);
    for (const [index, edge] of projection.edges.entries()) {
      const path = svgNode("path", { d: edge.path, "marker-end": "url(#task-map-arrow)", "data-map-edge": index,
        "data-source": edge.from, "data-target": edge.to, "data-relation": edge.relation, class: "task-map-edge" });
      const title = svgNode("title"); title.textContent = `${t(relationLabels[edge.relation] || "Caller-declared link")}: ${edge.from} → ${edge.to}`;
      path.append(title); svg.append(path);
    }
    canvas.append(svg);
    for (const lane of projection.lanes) {
      const heading = node("div", lane.reference ? t("Unresolved references") : lane.label, "task-map-lane");
      heading.style.left = `${lane.x}px`; heading.title = lane.reference ? t("Unresolved references") : lane.id;
      canvas.append(heading);
    }
    for (const item of projection.nodes) {
      const card = node("article", undefined, "task-map-node"); card.dataset.mapNode = item.id;
      card.style.left = `${item.x}px`; card.style.top = `${item.y}px`;
      if (item.reference) {
        card.classList.add("task-map-reference");
        card.append(node("strong", t(item.resolution === "ambiguous" ? "Ambiguous span" : "Unresolved span")), node("code", item.spanID),
          node("small", t(item.resolution === "ambiguous" ? "Multiple calls share this span. No target was chosen." : "No unique target is visible in this scope and observation window.")));
      } else {
        const call = item.call, record = call.record;
        const button = node("button", undefined, "task-map-inspect"); button.type = "button"; button.dataset.mapInspect = item.id;
        button.disabled = !!options.busy || !record;
        button.setAttribute("aria-label", t("Inspect task call {id}", { id: item.id }));
        const tags = node("span", undefined, "task-map-tags");
        if (item.context) tags.append(node("span", t("Related context"), "task-map-context"));
        if (item.state.blocked) tags.append(node("span", t("Blocked"), "task-map-risk"));
        if (item.state.matched) tags.append(node("span", t("Recorded match"), "task-map-risk"));
        if (item.state.attention) tags.append(node("span", t("Unknown or failed"), "task-map-unknown"));
        if (!tags.childElementCount) tags.append(node("span", t("No recorded match")));
        const identity = node("code", item.id); identity.title = item.id;
        const operation = node("strong", record?.operation || t("Call record unavailable"));
        const agent = node("span", t("Declared agent: {agent}", { agent: record?.trace?.agent_id || "—" })); agent.title = agent.textContent;
        button.append(tags, operation, identity, agent, node("small", record ? `${record.model || "—"} · ${record.outcome || t("Unknown")}` : t("Checks remain unknown.")));
        button.addEventListener("click", () => { selected = item.id; highlight(); inspect(call); });
        card.append(button);
        const availability = node("small", t(captureLabels[call.evidence_state]), "task-map-capture"); availability.title = availability.textContent;
        card.append(availability);
        if (!options.historical) {
          const evidence = node("button", t(call.evidence_state === "retained" ? "Open retained capture" : "Check current evidence"), "text-button task-map-evidence");
          evidence.type = "button"; evidence.dataset.mapEvidence = item.id; evidence.disabled = !!options.busy;
          evidence.addEventListener("click", () => { selected = item.id; highlight(); openEvidence(call); }); card.append(evidence);
        }
      }
      canvas.append(card);
    }
    highlight(); size();
  }

  search.addEventListener("input", draw); filter.addEventListener("change", draw);
  el("task-map-clear").addEventListener("click", () => { search.value = ""; filter.value = "all"; selected = ""; draw(); });
  el("task-map-zoom-out").addEventListener("click", () => { zoom = Math.max(0.6, Math.round((zoom - 0.2) * 10) / 10); size(); });
  el("task-map-zoom-in").addEventListener("click", () => { zoom = Math.min(1.4, Math.round((zoom + 0.2) * 10) / 10); size(); });
  el("task-map-reset").addEventListener("click", () => { zoom = 1; selected = ""; viewport.scrollTo(0, 0); size(); highlight(); });
  return {
    render(next, settings) {
      if (next !== view) { search.value = ""; filter.value = "all"; zoom = 1; selected = ""; viewport.scrollTo(0, 0); }
      view = next; options = settings; draw();
    },
    focus(id) {
      const card = [...canvas.querySelectorAll("[data-map-node]")].find(item => item.dataset.mapNode === id);
      if (!card) return;
      el("evidence-task-panel").open = true;
      card.scrollIntoView({ block: "center", inline: "center", behavior: "instant" });
      (card.querySelector("button:not(:disabled)") || viewport).focus({ preventScroll: true });
    },
  };
}
