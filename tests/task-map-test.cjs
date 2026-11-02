// Projection semantics only: these are synthetic metadata, not model assessments.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
async function main() {
  const moduleURL = source => `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`;
  const review = moduleURL(await fs.readFile('internal/server/web/request-review.js', 'utf8'));
  const source = (await fs.readFile('internal/server/web/task-map.js', 'utf8')).replace('/request-review.js', review);
  const { projectTaskMap, taskCallState } = await import(moduleURL(source));
  const call = (id, app, record = {}) => ({ request_id: id, application_id: app, evidence_state: 'retained', record: {
    request_id: id, application_id: app, operation: 'chat.completions', outcome: 'completed', ...record } });
  const edge = (from, to, relation = 'parent', resolution = 'observed', span = to) => ({ source_request_id: from,
    target_request_id: to, target_span_id: span, relation, resolution, provenance: 'caller_declared' });
  const a = call('a', 'app_a', { output_policy: { state: 'observed', result: 'observe', matched_categories: ['email'] } });
  const b = call('b', 'app_b'), c = call('c', 'app_b'), d = call('d', 'app_a');
  const missing = { request_id: 'index', application_id: 'app_a', evidence_state: 'unavailable' };
  const view = { application_ids: ['app_a', 'app_b'], calls: [a, b, c, d, missing, call('outside', 'app_x')],
    edges: [edge('a', 'b'), edge('b', 'c'), edge('a', 'a', 'retry_of'), edge('b', 'a', 'link'),
      edge('a', undefined, 'link', 'unresolved', 'span_missing'), edge('a', 'b', 'link', 'ambiguous', 'span_duplicate'), edge('outside', 'a')] };
  const all = projectTaskMap(view);
  assert.equal(all.nodes.filter(n => n.call).length, 5, 'never include another application');
  assert.equal(all.edges.length, 6);
  assert.ok(all.nodes.find(n => n.id === 'index').state.attention, 'index-only records are unknown');
  assert.ok(taskCallState(b).attention, 'missing recorded checks do not imply safety');
  assert.equal(taskCallState(a).matched, true, 'completed responses can contain detector matches');
  const filtered = projectTaskMap(view, { filter: 'matched' });
  assert.equal(filtered.matched, 1); assert.equal(filtered.related, 1); assert.equal(filtered.references, 2);
  assert.deepEqual(filtered.nodes.filter(n => n.call).map(n => [n.id, n.context]), [['a', false], ['b', true]]);
  assert.ok(!filtered.nodes.some(n => n.id === 'c' || n.id === 'd'), 'related context is one hop, not transitive');
  assert.equal(filtered.edges.find(e => e.relation === 'parent').to, 'b', 'arrow points at referenced parent');
  assert.equal(filtered.edges.find(e => e.resolution === 'ambiguous').to, 'reference:ambiguous:span_duplicate', 'ambiguous span never selects a real call');
  assert.ok(filtered.edges.every(e => !e.path.includes('NaN') && !e.path.includes('undefined')), 'cycles and self references have finite geometry');
  assert.deepEqual(projectTaskMap(view, { filter: 'matched' }), filtered, 'layout is deterministic');
  const options = { applications: [{ id: 'app_a', name: 'Current Name' }], query: 'current name' };
  assert.equal(projectTaskMap(view, options).matched, 3);
  assert.equal(projectTaskMap(view, { ...options, historical: true }).matched, 0, 'historical search must not use current names');
  const privateView = { ...view, calls: [{ ...a, record: { ...a.record, body: 'secret-marker' } }] };
  assert.equal(projectTaskMap(privateView, { query: 'secret-marker' }).matched, 0, 'metadata search must not serialize bodies');
  assert.equal(projectTaskMap(view, { query: '[.*]' }).matched, 0, 'query is literal');
  assert.equal(projectTaskMap(view, { filter: 'missing' }).matched, 1);
  const bounded = { application_ids: Array.from({ length: 16 }, (_, i) => `app_${i}`), calls: [], edges: [] };
  for (let i = 0; i < 128; i++) {
    bounded.calls.push(call(`req_${i}`, `app_${i % 16}`));
    for (let j = 0; j < 6; j++) bounded.edges.push(edge(`req_${i}`, undefined, 'link', 'unresolved', `span_${i}_${j}`));
  }
  const maximum = projectTaskMap(bounded);
  assert.equal(maximum.edges.length, 768); assert.equal(maximum.references, 768);
  assert.ok(Number.isFinite(maximum.width) && Number.isFinite(maximum.height));
  assert.throws(() => projectTaskMap({ ...bounded, edges: [...bounded.edges, bounded.edges[0]] }), /task_map_limit/);
  console.log('Task map semantics passed: scope, risk states, one-hop context, declared direction, missing/ambiguous targets, cycles, historical names, metadata-only search and bounds.');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
