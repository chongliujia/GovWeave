import { reviewRequest, matchesRequestSearch } from "/request-review.js";

// A projection of bounded, scoped observations, never a reconstruction of data flow.
export function taskCallState(call) {
  const review = reviewRequest(call.record || {});
  return { ...review, attention: !call.record || !review.checks.length || review.attention,
    missing: call.evidence_state !== "retained" };
}

export function projectTaskMap(view, { query = "", filter = "all", applications = [], historical = false } = {}) {
  if (!view) return { nodes: [], edges: [], lanes: [], width: 0, height: 0, matched: 0, related: 0, references: 0 };
  // The trace contract allows 128 calls, 16 applications, and six references per call.
  if (view.calls.length > 128 || view.application_ids.length > 16 || view.edges.length > 768) throw new Error("task_map_limit");
  const scope = new Set(view.application_ids);
  const calls = view.calls.filter(call => scope.has(call.application_id));
  const byID = new Map(calls.map(call => [call.request_id, call]));
  const name = id => historical ? id : applications.find(app => app.id === id)?.name || id;
  const matched = new Set(calls.filter(call => {
    const record = call.record || { request_id: call.request_id, application_id: call.application_id };
    return (filter === "all" || taskCallState(call)[filter]) && matchesRequestSearch(record, query, name(call.application_id));
  }).map(call => call.request_id));
  const validEdges = view.edges.filter(edge => byID.has(edge.source_request_id) && edge.provenance === "caller_declared");
  const targetID = edge => edge.resolution === "observed" && byID.has(edge.target_request_id) ? edge.target_request_id : null;
  const visible = new Set(matched);
  // One hop only; filtering must not silently present a related call as a match.
  for (const edge of validEdges) {
    const target = targetID(edge);
    if (target && (matched.has(edge.source_request_id) || matched.has(target))) {
      visible.add(edge.source_request_id); visible.add(target);
    }
  }
  const lanes = view.application_ids.filter(id => calls.some(call => visible.has(call.request_id) && call.application_id === id))
    .map(id => ({ id, label: name(id), reference: false }));
  const nodes = calls.filter(call => visible.has(call.request_id)).map(call => ({
    id: call.request_id, lane: call.application_id, call, context: !matched.has(call.request_id), state: taskCallState(call),
  }));
  const references = new Map(), edges = [];
  for (const edge of validEdges) {
    const target = targetID(edge);
    if (!visible.has(edge.source_request_id) || !(matched.has(edge.source_request_id) || target && matched.has(target))) continue;
    let to = target;
    if (!to) {
      const resolution = edge.resolution === "ambiguous" ? "ambiguous" : "unresolved";
      to = `reference:${resolution}:${edge.target_span_id}`;
      if (!references.has(to)) references.set(to, { id: to, lane: "references", reference: true, resolution, spanID: edge.target_span_id });
    }
    edges.push({ ...edge, from: edge.source_request_id, to });
  }
  if (references.size) { lanes.push({ id: "references", reference: true }); nodes.push(...references.values()); }
  const rowCounts = new Map();
  lanes.forEach((lane, index) => { lane.x = 24 + index * 368; });
  for (const item of nodes) {
    const row = rowCounts.get(item.lane) || 0; rowCounts.set(item.lane, row + 1);
    item.x = lanes.find(lane => lane.id === item.lane).x; item.y = 68 + row * 232;
    item.width = 304; item.height = 204;
  }
  const positions = new Map(nodes.map(item => [item.id, item]));
  for (const edge of edges) {
    const from = positions.get(edge.from), to = positions.get(edge.to);
    // References always point from the declaring call to the referenced call/span.
    const sameLane = from.x === to.x;
    const backwards = to.x < from.x;
    const x1 = backwards ? from.x : from.x + from.width, y1 = from.y + from.height / 2;
    const x2 = sameLane || backwards ? to.x + to.width : to.x, y2 = to.y + to.height / 2;
    const bend = sameLane ? x1 + 42 : (x1 + x2) / 2;
    edge.path = edge.from === edge.to
      ? `M ${x1} ${y1 - 30} C ${x1 + 58} ${y1 - 30}, ${x1 + 58} ${y1 + 30}, ${x1} ${y1 + 30}`
      : `M ${x1} ${y1} C ${bend} ${y1}, ${bend} ${y2}, ${x2} ${y2}`;
  }
  return { nodes, edges, lanes, width: lanes.length ? lanes.length * 368 + 24 : 0,
    height: nodes.length ? Math.max(...nodes.map(item => item.y + item.height)) + 24 : 0,
    matched: matched.size, related: visible.size - matched.size, references: references.size };
}
