// Isolated local content-evidence acceptance. No real model or real credentials.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawn } = require('node:child_process');
const { createHash } = require('node:crypto');

async function main() {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'govweave-evidence-'));
  const output = path.resolve('dist/evidence-smoke', new Date().toISOString().replace(/[:.]/g, '-'));
  await fs.mkdir(output, { recursive: true, mode: 0o700 });
  await fs.mkdir(path.join(directory, 'rule-packs'), { mode: 0o700 });
  await fs.copyFile(path.resolve('examples/rule-packs/demo-ai-governance.json'), path.join(directory, 'rule-packs/demo-ai-governance.json'));
  const providerKey = 'synthetic-evidence-provider-key';
  const privateEmail = 'forensic-fixture@private.example';
  const inputText = 'Synthetic private request marker 9ac874. Reply with one contact.';
  const answer = `Contact ${privateEmail}. <img src="https://never-fetch.example/image">`;
  const streamFrame = 'data: ' + JSON.stringify({ choices: [{ index: 0, delta: { content: answer }, finish_reason: null }] }) + '\r\n\r\n';
  const streamStart = ': fixture heartbeat\r\n\r\n' + streamFrame;
  const streamDone = 'data: [DONE]\r\n\r\n';
  const password = 'synthetic evidence administrator password';
  let calls = 0, browser, child;
  const failures = [], passed = [];
  const provider = http.createServer(async (req, res) => {
    assert.equal(req.headers.authorization, `Bearer ${providerKey}`);
    let raw = ''; for await (const chunk of req) raw += chunk;
    const input = JSON.parse(raw);
    assert.equal(input.model, 'fixture-model');
    calls++;
    if (input.stream) {
      res.setHeader('Content-Type', 'text/event-stream');
      const mode = input.messages[0].content;
      if (mode === 'oversize-stream') { res.end(streamFrame.repeat(132) + streamDone); return; }
      res.write(streamStart);
      await new Promise(resolve => setTimeout(resolve, 30));
      res.end(mode === 'incomplete-stream' ? '' : streamDone);
      return;
    }
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ id: 'fixture-completion', object: 'chat.completion', created: 1, model: 'fixture-model',
      choices: [{ index: 0, message: { role: 'assistant', content: answer }, finish_reason: 'stop' }] }));
  });
  await new Promise(resolve => provider.listen(0, '127.0.0.1', resolve));
  const reserve = http.createServer();
  await new Promise(resolve => reserve.listen(0, '127.0.0.1', resolve));
  const port = reserve.address().port;
  await new Promise(resolve => reserve.close(resolve));
  const origin = `http://127.0.0.1:${port}`;
  async function start() {
    const env = { ...process.env, GOVWEAVE_LISTEN_ADDR: `127.0.0.1:${port}`, GOVWEAVE_DATA_DIR: directory };
    for (const key of ['GOVWEAVE_PUBLIC_URL', 'GOVWEAVE_ORGANIZATION_NAME', 'GOVWEAVE_ADMIN_TOKEN_FILE']) delete env[key];
    child = spawn(path.resolve(process.env.GOVWEAVE_TEST_BINARY || 'bin/govweave'), [], { env, stdio: 'ignore' });
    for (let i = 0; i < 100; i++) {
      if (child.exitCode !== null) throw new Error('Evidence fixture exited during startup');
      try { if ((await fetch(origin + '/healthz')).ok) return; } catch {}
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw new Error('Evidence fixture did not start');
  }
  async function stop() {
    if (!child || child.exitCode !== null) return;
    const stopped = new Promise(resolve => child.once('exit', resolve));
    child.kill('SIGTERM');
    const timer = setTimeout(() => child.kill('SIGKILL'), 6000);
    await stopped; clearTimeout(timer);
  }
  try {
    await start();
    browser = await chromium.launch({ executablePath: process.env.GOVWEAVE_BROWSER_PATH || '/usr/bin/google-chrome', headless: true, args: ['--no-sandbox'] });
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    async function api(route, data, method = 'POST') {
      const response = await context.request.fetch(origin + route, { method, data, headers: { Origin: origin, 'Content-Type': 'application/json', 'X-GovWeave-Request': 'console' } });
      assert.equal(response.ok(), true, `${method} ${route}: ${response.status()}`);
      return response.json();
    }
    await api('/api/v1/auth/setup', { password });
    const model = await api('/api/v1/connections', { revision: 0, name: 'Evidence model fixture', base_url: `http://127.0.0.1:${provider.address().port}/v1`,
      model: 'fixture-model', alias: 'assistant', api_key: providerKey, enabled: true, allow_insecure_http: true, timeout_seconds: 2 });
    async function app(name) {
      const snapshot = await api('/api/v1/gateway', undefined, 'GET');
      return api('/api/v1/applications', { revision: snapshot.revision, name, allowed_connections: [model.id] });
    }
    const a = await app('Forensic fixture A'), b = await app('Isolated fixture B');
    async function chat(key, parent = '', relationships = {}) {
      const response = await fetch(origin + '/v1/chat/completions', { method: 'POST', headers: {
        Authorization: 'Bearer ' + key, 'Content-Type': 'application/json', 'X-GovWeave-Trace-ID': '1234567890abcdef1234567890abcdef',
        ...(parent ? { 'X-GovWeave-Parent-Span-ID': parent } : {}),
        ...(relationships.link ? { 'X-GovWeave-Link-Span-IDs': relationships.link } : {}),
        ...(relationships.retry ? { 'X-GovWeave-Retry-Of': relationships.retry } : {}),
      }, body: JSON.stringify({ model: 'assistant', messages: [{ role: 'user', content: inputText }], stream: false }) });
      const body = await response.json();
      return { status: response.status, body, id: response.headers.get('x-request-id'), span: response.headers.get('x-govweave-span-id') };
    }
    const disabled = await chat(a.api_key);
    assert.equal(disabled.status, 200);
    assert.equal((await api(`/api/v1/evidence?application_id=${a.application.id}`, undefined, 'GET')).items.length, 0);
    passed.push('capture_disabled_by_default');
    const page = await context.newPage();
    page.on('pageerror', error => failures.push(error.message));
    page.on('request', request => { if (!request.url().startsWith(origin + '/')) failures.push('External request from evidence UI'); });
    await page.goto(origin);
    await page.locator('#dashboard').waitFor({ state: 'visible' });
    await page.locator('#metric-apps').filter({ hasText: '02' }).waitFor();
    await page.locator('[data-tab="evidence"]').first().click();
    await page.locator('#evidence-config-panel').evaluate(element => { element.open = true; });
    await page.locator('#evidence-config-status[data-state="ready"]').waitFor();
    await page.locator('#evidence-mode').selectOption('full');
    await page.locator(`#evidence-app-options input[value="${a.application.id}"]`).check();
    await page.locator('#evidence-max-bytes').fill('65536');
    await page.locator('#evidence-save-config').click();
    await page.locator('#evidence-config-status[data-state="ready"]').waitFor();
    const config = await api('/api/v1/evidence/config', undefined, 'GET');
    assert.equal(config.mode, 'full'); assert.deepEqual(config.application_ids, [a.application.id]);
    passed.push('explicit_full_capture_scope_from_console');
    let policy = await api('/api/v1/policies/sensitive-output', undefined, 'GET');
    policy = await api('/api/v1/policies/sensitive-output', { revision: policy.revision, mode: 'block', detector_version: 'sensitive-text-v1', categories: ['email'], application_ids: [a.application.id] }, 'PUT');
    const blocked = await chat(a.api_key);
    assert.equal(blocked.status, 403);
    const evidenceID = 'ev_' + blocked.id.slice(4);
    const detail = await api(`/api/v1/evidence/${evidenceID}?application_id=${a.application.id}`, undefined, 'GET');
    assert.equal(detail.audit_committed, true);
    assert.equal(detail.delivery_state, 'withheld');
    assert.ok(detail.findings.some(finding => finding.category === 'email' && finding.result === 'block'));
    assert.ok(!JSON.stringify(detail).includes(privateEmail) && !JSON.stringify(detail).includes(inputText));
    assert.equal(detail.objects.find(object => object.kind === 'released_output').content_state, 'not_observed');
    const original = detail.objects.find(object => object.kind === 'upstream_output');
    assert.equal(original.content_state, 'retained');
    await page.locator('#evidence-app').selectOption(a.application.id);
    await page.locator(`[data-evidence-open="${evidenceID}"]`).click();
    const preview = page.locator(`[data-evidence-reveal="redacted"][data-object-id="${original.id}"]`);
    const raw = page.locator(`[data-evidence-reveal="raw"][data-object-id="${original.id}"]`);
    assert.equal(await raw.isDisabled(), true);
    assert.equal(await page.locator('#evidence-content').isVisible(), false);
    await preview.click();
    await page.locator('#evidence-content[data-state="redacted"]').waitFor();
    assert.ok(!(await page.locator('#evidence-content-text').textContent()).includes(privateEmail));
    await raw.click();
    await page.locator('#evidence-content[data-state="raw"]').waitFor();
    assert.ok((await page.locator('#evidence-content-text').textContent()).includes(privateEmail));
    assert.equal(await page.locator('#evidence-content-text img').count(), 0);
    const accesses = await api('/api/v1/evidence/access', undefined, 'GET');
    assert.equal(accesses.items.filter(item => item.action === 'reveal_authorized').length, 2);
    await page.locator('#evidence-hide-content').click();
    passed.push('original_blocked_output_review_with_audited_preview_and_raw_access');
    const wrongApp = await context.request.get(`${origin}/api/v1/evidence/${evidenceID}?application_id=${b.application.id}`);
    assert.equal(wrongApp.status(), 404);
    const noAdmin = await fetch(`${origin}/api/v1/evidence/${evidenceID}?application_id=${a.application.id}`, { headers: { Authorization: 'Bearer ' + a.api_key } });
    assert.equal(noAdmin.status, 401);
    const csrf = await context.request.post(`${origin}/api/v1/evidence/${evidenceID}/reveal`, { data: { application_id: a.application.id, object_id: original.id, view: 'raw', reason: 'validation' } });
    assert.equal(csrf.status(), 403);
    passed.push('application_keys_cross_application_queries_and_unprotected_reveal_denied');
    policy = await api('/api/v1/policies/sensitive-output', { revision: policy.revision, mode: 'redact', detector_version: 'sensitive-text-v1', categories: ['email'], application_ids: [a.application.id] }, 'PUT');
    const redacted = await chat(a.api_key, blocked.span);
    assert.equal(redacted.status, 200); assert.ok(!JSON.stringify(redacted.body).includes(privateEmail));
    const rid = 'ev_' + redacted.id.slice(4);
    const graph = await api(`/api/v1/evidence/${rid}/graph?application_id=${a.application.id}`, undefined, 'GET');
    assert.ok(graph.edges.some(edge => edge.relation === 'parent' && edge.provenance === 'caller_declared' && edge.resolution === 'observed'));
    assert.equal(graph.graph_complete, false);
    const redactedDetail = await api(`/api/v1/evidence/${rid}?application_id=${a.application.id}`, undefined, 'GET');
    const finalObject = redactedDetail.objects.find(object => object.kind === 'released_output');
    const finalContent = await api(`/api/v1/evidence/${rid}/reveal`, { application_id: a.application.id, object_id: finalObject.id, view: 'raw', reason: 'validation' });
    assert.ok(!finalContent.text.includes(privateEmail));
    assert.notEqual(finalObject.fingerprint, redactedDetail.objects.find(object => object.kind === 'upstream_output').fingerprint);
    passed.push('original_and_redacted_outputs_separated_with_declared_trace_graph');
    const product = await api('/api/v1/compliance/products', { revision: 0, name: 'Evidence assessment fixture', version: '1.0.0',
      application_ids: [a.application.id], pack_id: 'demo-ai-governance', pack_version: '1.0.0', facts: {
        'product.user_facing': { value: true, evidence_id: 'synthetic-profile', source: 'declared', observed_at: new Date().toISOString() },
      } });
    const report = await api(`/api/v1/compliance/products/${product.id}/reports`, {});
    const runtime = report.snapshot.report.runtime_evidence;
    assert.equal(runtime.coverage, 'gateway_observed_sample');
    assert.ok(runtime.records.some(record => record.request_id === blocked.id));
    for (const fact of runtime.facts) assert.equal(fact.value, fact.matched_request_ids.length);
    const blockedFact = runtime.facts.find(fact => fact.fact === 'runtime.sample.output_block_count');
    assert.deepEqual(blockedFact.matched_request_ids, [blocked.id]);
    assert.ok(!JSON.stringify(report).includes(privateEmail) && !JSON.stringify(report).includes(inputText));
    assert.equal((await api(`/api/v1/compliance/reports/${report.summary.id}/replay`, {})).matches, true);
    passed.push('assessment_report_retains_exact_counter_evidence_and_replays');
    // Evidence capture does not enable streaming output protection. Turn the
    // existing non-streaming output policy off before this independent trial.
    await api('/api/v1/policies/sensitive-output', { revision: policy.revision, mode: 'disabled', detector_version: 'sensitive-text-v1', categories: ['email'], application_ids: [a.application.id] }, 'PUT');
    async function streamChat(mode) {
      const response = await fetch(origin + '/v1/chat/completions', { method: 'POST', headers: {
        Authorization: 'Bearer ' + a.api_key, 'Content-Type': 'application/json',
      }, body: JSON.stringify({ model: 'assistant', messages: [{ role: 'user', content: mode }], stream: true }) });
      assert.equal(response.status, 200);
      let received = '', interrupted = false;
      const reader = response.body.getReader(), decoder = new TextDecoder();
      try {
        for (;;) { const result = await reader.read(); if (result.done) break; received += decoder.decode(result.value, { stream: true }); }
        received += decoder.decode();
      } catch { interrupted = true; }
      assert.equal(interrupted, mode === 'incomplete-stream');
      const id = 'ev_' + response.headers.get('x-request-id').slice(4);
      // A streaming response can end just before the terminal audit and vault
      // write complete. Poll the actual artifact, never infer it from the ID.
      for (let i = 0; i < 100; i++) {
        const found = await context.request.get(`${origin}/api/v1/evidence/${id}?application_id=${a.application.id}`);
        if (found.ok()) return { detail: await found.json(), received };
        assert.equal(found.status(), 404);
        await new Promise(resolve => setTimeout(resolve, 20));
      }
      throw new Error('Streaming evidence did not become available');
    }
    const streamed = await streamChat('complete-stream'), streamDetail = streamed.detail;
    assert.equal(streamed.received, streamStart + streamDone);
    assert.equal(streamDetail.delivery_state, 'write_completed');
    const streamOutput = streamDetail.objects.find(object => object.kind === 'upstream_output');
    const streamReleased = streamDetail.objects.find(object => object.kind === 'released_output');
    for (const object of [streamOutput, streamReleased]) {
      assert.equal(object.content_state, 'retained'); assert.equal(object.media_type, 'text/event-stream');
      assert.equal(object.stream.end_state, 'completed'); assert.equal(object.stream.frame_count, 3);
      assert.equal(object.stream.done_seen, true); assert.equal(object.stream.frames_truncated, false);
      assert.deepEqual(object.stream.frames.map(frame => frame.kind), ['other', 'data', 'done']);
    }
    assert.equal(streamOutput.stream.scope, 'validated_frames');
    assert.equal(streamReleased.stream.scope, 'write_attempted_frames');
    assert.equal(streamReleased.stream.written_bytes, Buffer.byteLength(streamed.received));
    assert.equal(streamOutput.fingerprint, streamReleased.fingerprint);
    const streamRaw = await api(`/api/v1/evidence/${streamDetail.id}/reveal`, { application_id: a.application.id, object_id: streamOutput.id, view: 'raw', reason: 'validation' });
    assert.equal(streamRaw.text, streamed.received);
    passed.push('stream_frames_retained_with_stage_scope_timeline_and_audited_content');
    const incompleteDetail = (await streamChat('incomplete-stream')).detail;
    for (const object of incompleteDetail.objects.filter(object => object.stream)) {
      assert.equal(object.stream.end_state, 'incomplete_stream');
      assert.equal(object.stream.done_seen, false); assert.equal(object.stream.frame_count, 2);
      assert.equal(object.content_state, 'retained');
    }
    assert.equal(incompleteDetail.record.outcome, 'failed');
    assert.equal(incompleteDetail.delivery_state, 'stream_incomplete');
    passed.push('incomplete_stream_keeps_observed_frames_without_completion_claim');
    let captureConfig = await api('/api/v1/evidence/config', undefined, 'GET');
    captureConfig = await api('/api/v1/evidence/config', { ...captureConfig, max_content_bytes: 4096 }, 'PUT');
    const oversizeDetail = (await streamChat('oversize-stream')).detail;
    for (const object of oversizeDetail.objects.filter(object => object.stream)) {
      assert.equal(object.content_state, 'omitted_size'); assert.ok(object.bytes > 4096);
      assert.equal(object.stream.frame_count, 133); assert.equal(object.stream.frames.length, 128);
      assert.equal(object.stream.frames_truncated, true); assert.equal(object.stream.done_seen, true);
      const withheld = await context.request.post(`${origin}/api/v1/evidence/${oversizeDetail.id}/reveal`, { data: { application_id: a.application.id, object_id: object.id, view: 'raw', reason: 'validation' }, headers: { Origin: origin, 'X-GovWeave-Request': 'console' } });
      assert.equal(withheld.status(), 409);
    }
    captureConfig = await api('/api/v1/evidence/config', { ...captureConfig, mode: 'metadata' }, 'PUT');
    const metadataDetail = (await streamChat('complete-stream')).detail;
    for (const object of metadataDetail.objects.filter(object => object.stream)) {
      assert.equal(object.content_state, 'metadata_only'); assert.ok(object.fingerprint);
      assert.equal(object.stream.end_state, 'completed');
    }
    passed.push('stream_capture_limits_keep_counts_and_fingerprints_without_body');
    const uncapturedWorker = await chat(b.api_key, blocked.span);
    assert.equal(uncapturedWorker.status, 200);
    captureConfig = await api('/api/v1/evidence/config', { ...captureConfig, application_ids: [a.application.id, b.application.id] }, 'PUT');
    const capturedWorker = await chat(b.api_key, redacted.span, { link: blocked.span, retry: uncapturedWorker.span });
    assert.equal(capturedWorker.status, 200);
    const taskPath = '/api/v1/evidence-traces/1234567890abcdef1234567890abcdef';
    const singleTaskView = await api(`${taskPath}?application_id=${a.application.id}&limit=128`, undefined, 'GET');
    assert.equal(singleTaskView.calls.length, 3);
    assert.ok(!JSON.stringify(singleTaskView).includes(b.application.id));
    const taskView = await api(`${taskPath}?application_id=${a.application.id}&application_id=${b.application.id}&limit=128`, undefined, 'GET');
    assert.equal(taskView.calls.length, 5);
    assert.equal(taskView.summary.retained, 3); assert.equal(taskView.summary.not_found, 2);
    assert.equal(taskView.task_completion, 'not_determined'); assert.equal(taskView.graph_complete, false);
    assert.equal(taskView.finding_coverage, 'retained_evidence_only');
    assert.ok(taskView.edges.some(edge => edge.relation === 'retry_of' && edge.source_request_id === capturedWorker.id && edge.target_request_id === uncapturedWorker.id && edge.provenance === 'caller_declared' && edge.resolution === 'observed'));
    const missingCall = taskView.calls.find(call => call.request_id === uncapturedWorker.id);
    assert.equal(missingCall.evidence_state, 'not_found'); assert.deepEqual(missingCall.findings, []);
    assert.ok(!JSON.stringify(taskView).includes(privateEmail) && !JSON.stringify(taskView).includes(inputText));
    assert.equal((await fetch(origin + taskPath + '?application_id=' + a.application.id, { headers: { Authorization: 'Bearer ' + a.api_key } })).status, 401);
    passed.push('task_evidence_joins_explicit_apps_with_declared_edges_and_capture_gaps');
    const taskScope = `?application_id=${a.application.id}&application_id=${b.application.id}`;
    const taskArchive = await api(`${taskPath}/snapshots${taskScope}&limit=128`, { expected_view_sha256: taskView.view_sha256 });
    assert.deepEqual(taskArchive.snapshot.view, taskView);
    assert.equal(taskArchive.integrity, 'authenticated_local');
    const taskArchiveList = await api(`${taskPath}/snapshots${taskScope}`, undefined, 'GET');
    assert.equal(taskArchiveList.items.length, 1);
    assert.equal((await api(`${taskPath}/snapshots?application_id=${a.application.id}`, undefined, 'GET')).items.length, 0);
    const archivePath = `${taskPath}/snapshots/${taskArchive.summary.id}`;
    assert.equal((await context.request.get(`${origin}${archivePath}?application_id=${a.application.id}`)).status(), 404);
    assert.equal((await fetch(`${origin}${archivePath}/export/json${taskScope}`, { headers: { Authorization: 'Bearer ' + a.api_key } })).status, 401);
    passed.push('task_snapshot_exact_scope_and_application_key_export_denial');
    await stop(); await start();
    await api('/api/v1/auth/login', { password });
    assert.deepEqual(await api(`${archivePath}${taskScope}`, undefined, 'GET'), taskArchive);
    assert.equal((await api(`/api/v1/evidence/${evidenceID}?application_id=${a.application.id}`, undefined, 'GET')).id, evidenceID);
    await page.reload(); await page.locator('#metric-apps').filter({ hasText: '02' }).waitFor();
    await page.locator('[data-tab="evidence"]').first().click();
    await page.locator('#evidence-app').selectOption(a.application.id);
    await page.locator(`[data-evidence-open="${rid}"]`).click();
    await page.locator('#evidence-graph-nodes li').first().waitFor();
    await page.locator('#console-language').selectOption('zh-CN');
    assert.equal(await page.locator('#evidence-content').isVisible(), false);
    await page.screenshot({ path: path.join(output, 'evidence-zh.png'), fullPage: true, animations: 'disabled' });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    await page.locator('#evidence-detail').evaluate(element => element.scrollIntoView({ block: 'start', behavior: 'instant' }));
    await page.screenshot({ path: path.join(output, 'evidence-mobile-detail.png'), animations: 'disabled' });
    await page.locator('#evidence-objects').scrollIntoViewIfNeeded();
    await page.screenshot({ path: path.join(output, 'evidence-mobile-objects.png'), animations: 'disabled' });
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'instant' }));
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await page.screenshot({ path: path.join(output, 'evidence-mobile-zh.png'), fullPage: true, animations: 'disabled' });
    passed.push('encrypted_evidence_survives_restart_and_bilingual_layouts');
    await page.locator(`[data-evidence-open="${streamDetail.id}"]`).click();
    const streamCard = page.locator(`[data-object-id="${streamOutput.id}"]`).filter({ has: page.locator('.evidence-stream') });
    await streamCard.locator('.evidence-stream-timeline summary').click();
    assert.equal(await streamCard.locator('.evidence-stream-timeline li').count(), 3);
    assert.equal(await streamCard.locator('.evidence-stream').getAttribute('data-end-state'), 'completed');
    await streamCard.evaluate(element => element.scrollIntoView({ block: 'start', behavior: 'instant' }));
    await page.screenshot({ path: path.join(output, 'evidence-stream-mobile.png'), animations: 'disabled' });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    await page.locator(`[data-evidence-open="${incompleteDetail.id}"]`).click();
    await page.locator('.evidence-stream[data-end-state="incomplete_stream"]').first().waitFor();
    assert.equal(await page.locator('#evidence-content').isVisible(), false);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.locator('.evidence-stream').first().evaluate(element => element.scrollIntoView({ block: 'start', behavior: 'instant' }));
    await page.screenshot({ path: path.join(output, 'evidence-stream-incomplete.png'), animations: 'disabled' });
    passed.push('stream_timeline_and_incomplete_state_render_after_restart');
    await page.locator('#evidence-task-panel').evaluate(element => { element.open = true; });
    assert.equal(await page.locator('#evidence-task-app-options input:checked').count(), 0);
    await page.locator('#evidence-task-trace').fill('1234567890abcdef1234567890abcdef');
    await page.locator(`#evidence-task-app-options input[value="${a.application.id}"]`).check();
    await page.locator('#evidence-task-load').click();
    await page.locator('#evidence-task-status[data-state="ready"]').waitFor();
    assert.equal(await page.locator('#evidence-task-calls tr').count(), 3);
    await page.locator(`#evidence-task-app-options input[value="${b.application.id}"]`).check();
    assert.equal(await page.locator('#evidence-task-results').isVisible(), false);
    await page.locator('#evidence-task-load').click();
    await page.locator('#evidence-task-status[data-state="ready"]').waitFor();
    assert.equal(await page.locator('#evidence-task-calls tr').count(), 5);
    const workerEvidence = 'ev_' + capturedWorker.id.slice(4);
    await page.locator(`[data-task-evidence="${workerEvidence}"]`).click();
    await page.locator(`#evidence-detail-fields dd`).filter({ hasText: workerEvidence }).waitFor();
    assert.equal(await page.locator('#evidence-app').inputValue(), b.application.id);
    assert.equal(await page.locator('#evidence-content').isVisible(), false);
    await page.locator('#evidence-task-results').evaluate(element => element.scrollIntoView({ block: 'start', behavior: 'instant' }));
    await page.screenshot({ path: path.join(output, 'evidence-task-zh.png'), animations: 'disabled' });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    await page.locator('#evidence-task-panel').evaluate(element => element.scrollIntoView({ block: 'start', behavior: 'instant' }));
    await page.screenshot({ path: path.join(output, 'evidence-task-mobile.png'), animations: 'disabled' });
    passed.push('task_evidence_scope_selection_and_capture_drilldown_after_restart');
    // A new non-inference observation changes the displayed view's digest.
    const changed = await context.request.post(`${origin}/v1/content/evaluations`, { data: { text: 'Synthetic snapshot observation' }, headers: { Authorization: 'Bearer ' + a.api_key, 'X-GovWeave-Trace-ID': taskView.trace_id } });
    assert.equal(changed.status(), 200);
    await page.locator('#evidence-task-save').click();
    await page.locator('#evidence-task-archive-status[data-state="changed"]').waitFor();
    assert.equal(await page.locator('#evidence-task-snapshot').isVisible(), false);
    await page.locator('#evidence-task-load').click();
    await page.locator('#evidence-task-calls tr').nth(5).waitFor();
    await page.locator('#evidence-task-save').click();
    await page.locator('#evidence-task-archive-status[data-state="saved"]').waitFor();
    assert.equal(await page.locator('#evidence-task-status').getAttribute('data-state'), 'archived');
    assert.equal(await page.locator('#evidence-task-calls tr').count(), 6);
    assert.equal(await page.locator('#evidence-task-save').isDisabled(), true);
    assert.equal(await page.locator('#evidence-content').isVisible(), false);
    passed.push('task_snapshot_save_rejects_changed_view_then_saves_exact_reloaded_view');
    await page.locator('#evidence-task-archives-load').click();
    await page.locator('[data-task-snapshot]').nth(1).waitFor();
    await page.locator(`[data-task-snapshot="${taskArchive.summary.id}"]`).click();
    await page.locator('#evidence-task-archive-status[data-state="opened"]').waitFor();
    assert.equal(await page.locator('#evidence-task-calls tr').count(), 5);
    assert.equal(await page.locator('[data-task-evidence]').count(), 0);
    for (const format of ['json', 'markdown']) {
      const downloadPromise = page.waitForEvent('download');
      await page.locator(`#evidence-task-export-${format}`).click();
      const download = await downloadPromise;
      const destination = path.join(output, format === 'json' ? 'snapshot-export.json' : 'snapshot-report.md');
      await download.saveAs(destination);
      const bytes = await fs.readFile(destination);
      assert.ok(!bytes.includes(Buffer.from(privateEmail)) && !bytes.includes(Buffer.from(inputText)));
      if (format === 'json') {
        assert.deepEqual(JSON.parse(bytes), taskArchive.snapshot);
        assert.equal(createHash('sha256').update(bytes).digest('hex'), taskArchive.summary.sha256);
        assert.equal(bytes.length, taskArchive.summary.bytes);
      } else {
        assert.ok(bytes.includes(Buffer.from(taskArchive.summary.sha256)) && bytes.includes(Buffer.from('caller_declared')));
      }
    }
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.locator('#evidence-task-snapshot').evaluate(element => element.scrollIntoView({ block: 'start', behavior: 'instant' }));
    await page.screenshot({ path: path.join(output, 'task-snapshot-desktop.png'), animations: 'disabled' });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    await page.locator('#evidence-task-snapshot').evaluate(element => element.scrollIntoView({ block: 'start', behavior: 'instant' }));
    await page.screenshot({ path: path.join(output, 'task-snapshot-mobile.png'), animations: 'disabled' });
    passed.push('historical_task_snapshot_reopens_after_restart_and_downloads_exact_metadata');
    let releaseSnapshot, fetchedSnapshot;
    const snapshotGate = new Promise(resolve => { releaseSnapshot = resolve; });
    const snapshotFetched = new Promise(resolve => { fetchedSnapshot = resolve; });
    const snapshotPattern = `**${archivePath}?*`;
    await page.route(snapshotPattern, async route => {
      const response = await route.fetch(); fetchedSnapshot(); await snapshotGate; await route.fulfill({ response });
    });
    try {
      await page.locator(`[data-task-snapshot="${taskArchive.summary.id}"]`).click();
      await snapshotFetched;
      await page.locator(`#evidence-task-app-options input[value="${b.application.id}"]`).uncheck();
      const lateSnapshot = page.waitForResponse(response => response.url().includes(archivePath));
      releaseSnapshot(); await lateSnapshot;
      await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      assert.equal(await page.locator('#evidence-task-snapshot').isVisible(), false);
      assert.equal(await page.locator('#evidence-task-results').isVisible(), false);
      assert.equal(await page.locator('#evidence-task-export-json').getAttribute('href'), null);
    } finally { releaseSnapshot(); await page.unroute(snapshotPattern); }
    await page.locator(`#evidence-task-app-options input[value="${b.application.id}"]`).check();
    passed.push('late_snapshot_response_cannot_restore_previous_scope_or_downloads');
    // A late response for a larger scope must not resurrect cleared results.
    let releaseTask, fetchedTask;
    const taskGate = new Promise(resolve => { releaseTask = resolve; });
    const taskFetched = new Promise(resolve => { fetchedTask = resolve; });
    await page.route('**/api/v1/evidence-traces/**', async route => {
      const response = await route.fetch(); fetchedTask(); await taskGate; await route.fulfill({ response });
    });
    try {
      await page.locator('#evidence-task-load').click();
      await taskFetched;
      await page.locator(`#evidence-task-app-options input[value="${b.application.id}"]`).uncheck();
      const lateResponse = page.waitForResponse(response => response.url().includes('/api/v1/evidence-traces/'));
      releaseTask(); await lateResponse;
      await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      assert.equal(await page.locator('#evidence-task-results').isVisible(), false);
      assert.equal(await page.locator('#evidence-task-status').getAttribute('data-state'), 'idle');
    } finally { releaseTask(); await page.unroute('**/api/v1/evidence-traces/**'); }
    passed.push('late_task_response_cannot_restore_previous_application_scope');
    await page.locator('#evidence-app').selectOption(a.application.id);
    await page.locator(`[data-evidence-open="${rid}"]`).click();
    await page.locator('#console-language').selectOption('en');
    await page.locator(`[data-evidence-reveal="redacted"][data-object-id="${finalObject.id}"]`).click();
    await page.locator('#evidence-content[data-state="redacted"]').waitFor();
    await page.locator('#evidence-app').selectOption(b.application.id);
    assert.equal(await page.locator('#evidence-content-text').textContent(), '');
    const storage = await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }));
    const audit = await fs.readFile(path.join(directory, 'calls.jsonl'), 'utf8');
    for (const secret of [privateEmail, inputText, providerKey, a.api_key, b.api_key]) {
      assert.ok(!storage.includes(secret) && !audit.includes(secret));
      for (const file of await fs.readdir(path.join(directory, 'evidence'))) {
        assert.ok(!(await fs.readFile(path.join(directory, 'evidence', file))).includes(Buffer.from(secret)));
      }
      for (const file of await fs.readdir(path.join(directory, 'task-evidence'))) {
        assert.ok(!(await fs.readFile(path.join(directory, 'task-evidence', file))).includes(Buffer.from(secret)));
      }
    }
    passed.push('no_plaintext_vault_or_call_logs_browser_storage_and_selection_clear');
    assert.deepEqual(failures, []);
    for (const [name, value] of Object.entries({ config, detail, graph, redactedDetail, report, streamDetail, incompleteDetail, oversizeDetail, metadataDetail, taskView, singleTaskView, taskArchive, taskArchiveList })) {
      await fs.writeFile(path.join(output, name + '.json'), JSON.stringify(value, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    }
    await fs.writeFile(path.join(output, 'summary.json'), JSON.stringify({ passed, provider_calls: calls, scope: 'Local gateway and actual browser with synthetic provider. No real API calls, Docker test, independent root-cause proof or legal certification.' }, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    console.log(`Evidence checks passed (${passed.length} groups, ${calls} synthetic model calls): ${output}`);
  } finally {
    if (browser) await browser.close();
    await stop(); provider.closeAllConnections(); await new Promise(resolve => provider.close(resolve));
    await fs.rm(directory, { recursive: true, force: true });
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
