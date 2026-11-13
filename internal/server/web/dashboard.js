import { t, getLocale, formatTime } from "/i18n.js";
import { reviewRequest } from "/request-review.js";

const series = [
  { key: "completed", label: "Completed" },
  { key: "blocked", label: "Blocked / rejected" },
  { key: "failed", label: "Failed" },
  { key: "other", label: "Other outcomes" },
];
const counts = () => ({ completed: 0, blocked: 0, failed: 0, other: 0 });
const element = id => document.getElementById(id);
const node = (tag, text, className) => {
  const value = document.createElement(tag);
  if (text !== undefined) value.textContent = text;
  if (className) value.className = className;
  return value;
};
const svgNode = (tag, attributes, text) => {
  const value = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, content] of Object.entries(attributes)) value.setAttribute(key, String(content));
  if (text !== undefined) value.textContent = text;
  return value;
};

export function summarizeActivity(records, { days = 7, model = "", now = Date.now() } = {}) {
  if (![1, 7, 30].includes(days) || !Number.isFinite(now)) throw new Error("invalid_activity_range");
  const duration = days * 86400000, start = now - duration, bucketCount = days === 1 ? 24 : days;
  const bucketWidth = duration / bucketCount;
  const buckets = Array.from({ length: bucketCount }, (_, index) => ({ start: start + index * bucketWidth, total: 0, ...counts() }));
  const totals = counts();
  let total = 0, omitted = 0;
  for (const record of records) {
    if (model && record.model !== model) continue;
    const timestamp = Date.parse(record.started_at);
    if (!Number.isFinite(timestamp) || timestamp > now) { omitted++; continue; }
    if (timestamp < start) continue;
    const outcome = record.outcome === "completed" ? "completed" : ["blocked", "rejected"].includes(record.outcome) ? "blocked" : record.outcome === "failed" ? "failed" : "other";
    const index = Math.min(bucketCount - 1, Math.floor((timestamp - start) / bucketWidth));
    buckets[index][outcome]++;
    buckets[index].total++;
    totals[outcome]++;
    total++;
  }
  return { buckets, totals, total, omitted, start, end: now };
}

export function selectReviewRecords(records) {
  return records.filter(record => {
    const review = reviewRequest(record);
    return review.matched || review.blocked || review.attention;
  }).slice(0, 5);
}

export function createDashboard({ inspectRequest, applicationName }) {
  let snapshot = null, days = 7, model = "", observedAt = Date.now(), unavailable = false;
  const number = value => value.toLocaleString(getLocale());

  function chart(summary) {
    const container = element("traffic-chart");
    const canvasWidth = Math.max(280, container.clientWidth);
    const svg = svgNode("svg", { viewBox: `0 0 ${canvasWidth} 270`, role: "img", "aria-label": t("Sampled request activity by outcome") });
    svg.append(svgNode("title", {}, t("{count} recorded calls in the selected range", { count: number(summary.total) })));
    const left = 36, right = canvasWidth - 12, top = 16, bottom = 234, width = right - left, height = bottom - top;
    const peak = Math.max(1, ...summary.buckets.map(bucket => bucket.total));
    const step = Math.max(1, Math.ceil(peak / 4)), maximum = step * 4;
    for (let index = 0; index <= 4; index++) {
      const position = bottom - height * index / 4;
      svg.append(svgNode("line", { x1: left, x2: right, y1: position, y2: position, class: "chart-grid" }));
      svg.append(svgNode("text", { x: left - 10, y: position + 4, "text-anchor": "end" }, number(step * index)));
    }
    const spacing = width / summary.buckets.length, barWidth = Math.min(42, spacing * .58);
    const dateFormat = new Intl.DateTimeFormat(getLocale(), days === 1 ? { hour: "2-digit", hourCycle: "h23", timeZone: "UTC" } : { month: "2-digit", day: "2-digit", timeZone: "UTC" });
    const labelEvery = Math.ceil(summary.buckets.length / (canvasWidth < 480 ? 4 : 6));
    for (const [index, bucket] of summary.buckets.entries()) {
      const center = left + spacing * (index + .5), label = dateFormat.format(new Date(bucket.start));
      if (index % labelEvery === 0) svg.append(svgNode("text", { x: center, y: 260, "text-anchor": "middle" }, label));
      if (!bucket.total) continue;
      const description = `${new Date(bucket.start).toISOString()} · ${series.map(item => `${t(item.label)}: ${number(bucket[item.key])}`).join(" · ")}`;
      const group = svgNode("g", { role: "img", tabindex: "0", "aria-label": description });
      group.append(svgNode("title", {}, description));
      let offset = 0;
      for (const item of series) {
        const barHeight = bucket[item.key] / maximum * height;
        if (barHeight) group.append(svgNode("rect", { x: center - barWidth / 2, y: bottom - offset - barHeight, width: barWidth, height: barHeight, rx: 2, class: "chart-bar", "data-series": item.key }));
        offset += barHeight;
      }
      svg.append(group);
    }
    if (!summary.total) {
      const center = left + width / 2;
      svg.append(svgNode("rect", { x: left, y: 94, width, height: 66, fill: "white", rx: 8 }));
      svg.append(svgNode("text", { x: center, y: 120, "text-anchor": "middle", class: "chart-empty" }, t("No recorded calls in this range")));
      svg.append(svgNode("text", { x: center, y: 142, "text-anchor": "middle", class: "chart-empty-detail" }, t("Try another range or model.")));
    }
    container.replaceChildren(svg);
  }

  function emptyPanel(title, message) {
    const empty = node("div", undefined, "panel-empty");
    empty.append(node("span", "↗", "empty-symbol"), node("strong", title), node("p", message));
    return empty;
  }

  function renderReviews() {
    const container = element("overview-findings");
    container.replaceChildren();
    if (!snapshot) {
      container.append(emptyPanel(t(unavailable ? "Request records unavailable" : "Waiting for request records"), t(unavailable ? "Refresh to try again" : "Recorded findings will appear here.")));
      return;
    }
    const records = selectReviewRecords(snapshot.records);
    if (!records.length) {
      container.append(emptyPanel(t("No review items in this sample"), t("No recorded matches or calls needing attention. This is not a safety or compliance conclusion.")));
    }
    for (const record of records) {
      const review = reviewRequest(record), row = node("article", undefined, "finding-row");
      const label = node("span", t(review.matched ? "Match" : review.blocked ? "Blocked" : "Needs review"), "finding-label");
      label.dataset.kind = review.matched ? "matched" : "attention";
      const detail = node("div"), checks = review.checks.filter(check => check.rules.length || check.categories.length || check.unknown);
      detail.append(node("strong", applicationName(record)));
      detail.append(node("p", checks.length ? checks.map(check => t(check.label)).join(" · ") : record.error_code || t("Review the recorded request outcome.")));
      detail.append(node("time", formatTime(record.started_at), "finding-time"));
      const inspect = node("button", "↗", "text-button");
      inspect.type = "button";
      inspect.setAttribute("aria-label", t("Inspect request {id}", { id: record.request_id }));
      inspect.addEventListener("click", () => inspectRequest(record));
      row.append(label, detail, inspect);
      container.append(row);
    }
  }

  function render() {
    const select = element("traffic-model"), models = [...new Set((snapshot?.records || []).map(record => record.model).filter(Boolean))].sort();
    if (!models.includes(model)) model = "";
    select.replaceChildren(new Option(t("All models and tools"), ""), ...models.map(name => new Option(name, name)));
    select.value = model;
    select.disabled = !snapshot;
    document.querySelectorAll("[data-traffic-period]").forEach(button => { button.setAttribute("aria-pressed", String(Number(button.dataset.trafficPeriod) === days)); });
    element("traffic-legend").replaceChildren(...series.map(item => {
      const label = node("span", t(item.label)); label.dataset.series = item.key; return label;
    }));
    const summary = summarizeActivity(snapshot?.records || [], { days, model, now: observedAt });
    element("traffic-total").textContent = snapshot ? number(summary.total) : "—";
    element("metric-matches").textContent = snapshot ? number(snapshot.records.filter(record => reviewRequest(record).matched).length) : "—";
    element("traffic-breakdown").replaceChildren(...series.map(item => {
      const stat = node("div"), heading = node("div", undefined, "traffic-stat-heading"), track = node("div", undefined, "traffic-stat-track"), fill = node("div", undefined, "traffic-stat-fill");
      stat.dataset.series = item.key;
      heading.append(node("span", t(item.label)), node("strong", snapshot ? number(summary.totals[item.key]) : "—"));
      fill.style.width = `${summary.total ? summary.totals[item.key] / summary.total * 100 : 0}%`;
      track.append(fill); stat.append(heading, track); return stat;
    }));
    if (snapshot) chart(summary);
    else element("traffic-chart").replaceChildren(emptyPanel(t(unavailable ? "Request records unavailable" : "Waiting for request records"), t("Refresh to load the latest sample.")));
    const messages = [];
    if (snapshot) messages.push(t("{count} recorded calls in the selected range", { count: number(summary.total) }));
    if (summary.omitted) messages.push(t("{count} records have unusable timestamps", { count: number(summary.omitted) }));
    if (snapshot && !snapshot.available) messages.push(t("Logging unavailable · New requests stopped"));
    element("traffic-status").textContent = messages.join(" · ");
    renderReviews();
  }

  element("traffic-model").addEventListener("change", event => { model = event.target.value; render(); });
  document.querySelectorAll("[data-traffic-period]").forEach(button => button.addEventListener("click", () => { days = Number(button.dataset.trafficPeriod); render(); }));
  let chartWidth = 0;
  const observer = new ResizeObserver(entries => {
    const width = Math.round(entries[0].contentRect.width);
    if (width !== chartWidth) {
      chartWidth = width;
      if (snapshot && width) chart(summarizeActivity(snapshot.records, { days, model, now: observedAt }));
    }
  });
  observer.observe(element("traffic-chart"));
  return {
    render(view, time, failed = false) { snapshot = view; observedAt = time?.getTime() || Date.now(); unavailable = failed; render(); },
    reset() { snapshot = null; model = ""; days = 7; unavailable = false; observedAt = Date.now(); render(); },
  };
}
