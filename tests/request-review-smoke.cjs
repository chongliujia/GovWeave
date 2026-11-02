// Actual browser + local gateway; only synthetic requests and credentials.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawn } = require('node:child_process');

async function main() {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'govweave-review-'));
  const output = path.resolve('dist/request-review-smoke', new Date().toISOString().replace(/[:.]/g, '-'));
  await fs.mkdir(output, { recursive: true, mode: 0o700 });
  const privateEmail = 'synthetic-contact@private.example', privatePrompt = 'Synthetic review prompt 9ef812.';
  const trace = '1234567890abcdef1234567890abcdef';
  const failures = [], passed = [], requests = [];
  let child, browser, releaseHeld, calls = 0;
  const provider = http.createServer(async (req, res) => {
    let raw = ''; for await (const chunk of req) raw += chunk;
    const input = JSON.parse(raw); calls++;
    res.setHeader('Content-Type', 'application/json');
    if (input.messages[0].content === 'invalid-fixture') { res.end('{}'); return; }
    res.end(JSON.stringify({ id: 'fixture', object: 'chat.completion', model: 'fixture-model', created: 1,
      choices: [{ index: 0, message: { role: 'assistant', content: privateEmail }, finish_reason: 'stop' }] }));
  });
  await new Promise(resolve => provider.listen(0, '127.0.0.1', resolve));
  const reserve = http.createServer();
  await new Promise(resolve => reserve.listen(0, '127.0.0.1', resolve));
  const port = reserve.address().port; await new Promise(resolve => reserve.close(resolve));
  const origin = `http://127.0.0.1:${port}`;
  try {
    const env = { ...process.env, GOVWEAVE_LISTEN_ADDR: `127.0.0.1:${port}`, GOVWEAVE_DATA_DIR: directory };
    for (const key of ['GOVWEAVE_PUBLIC_URL', 'GOVWEAVE_ORGANIZATION_NAME', 'GOVWEAVE_ADMIN_TOKEN_FILE']) delete env[key];
    child = spawn(path.resolve(process.env.GOVWEAVE_TEST_BINARY || 'bin/govweave'), [], { env, stdio: 'ignore' });
    for (let i = 0; i < 100; i++) {
      try { if ((await fetch(origin + '/healthz')).ok) break; } catch {}
      if (i === 99 || child.exitCode !== null) throw new Error('Local gateway failed to start');
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    browser = await chromium.launch({ executablePath: process.env.GOVWEAVE_BROWSER_PATH || '/usr/bin/google-chrome', headless: true, args: ['--no-sandbox'] });
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    async function api(route, data, method = 'POST') {
      const response = await context.request.fetch(origin + route, { method, data,
        headers: { 'Content-Type': 'application/json', 'X-GovWeave-Request': 'console', Origin: origin } });
      assert.equal(response.ok(), true, `${method} ${route}: ${response.status()}`); return response.json();
    }
    await api('/api/v1/auth/setup', { password: 'synthetic review administrator password' });
    let snapshot = await api('/api/v1/gateway', undefined, 'GET');
    const model = await api('/api/v1/connections', { revision: snapshot.revision, name: 'Review model', alias: 'assistant',
      model: 'fixture-model', base_url: `http://127.0.0.1:${provider.address().port}/v1`, api_key: 'synthetic-review-provider-key',
      enabled: true, allow_insecure_http: true, timeout_seconds: 2 });
    async function app(name) {
      snapshot = await api('/api/v1/gateway', undefined, 'GET');
      return api('/api/v1/applications', { revision: snapshot.revision, name, allowed_connections: [model.id] });
    }
    const a = await app('Support Agent'), b = await app('Knowledge Agent');
    const capture = await api('/api/v1/evidence/config', undefined, 'GET');
    await api('/api/v1/evidence/config', { ...capture, mode: 'full', application_ids: [a.application.id] }, 'PUT');
    const input = await api('/api/v1/policies/credential-egress', undefined, 'GET');
    await api('/api/v1/policies/credential-egress', { revision: input.revision, mode: 'block', rules: ['private_key', 'api_key'], application_ids: [a.application.id], connection_ids: [] }, 'PUT');
    const policy = await api('/api/v1/policies/sensitive-output', undefined, 'GET');
    await api('/api/v1/policies/sensitive-output', { revision: policy.revision, mode: 'observe', detector_version: 'sensitive-text-v1', categories: ['email'], application_ids: [a.application.id] }, 'PUT');
    async function invoke(key, content = privatePrompt) {
      const response = await fetch(origin + '/v1/chat/completions', { method: 'POST', headers: {
        'Content-Type': 'application/json', Authorization: `Bearer ${key}`, 'X-GovWeave-Trace-ID': trace,
      }, body: JSON.stringify({ model: 'assistant', messages: [{ role: 'user', content }] }) });
      await response.text(); return { id: response.headers.get('x-request-id'), status: response.status };
    }
    const observed = await invoke(a.api_key), normal = await invoke(b.api_key);
    const blocked = await invoke(a.api_key, '-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----');
    const failed = await invoke(a.api_key, 'invalid-fixture');
    assert.equal(observed.status, 200); assert.equal(normal.status, 200); assert.equal(blocked.status, 403); assert.equal(failed.status, 502);
    const page = await context.newPage();
    page.on('pageerror', error => failures.push(error.message));
    page.on('request', request => { requests.push(request.url()); if (!request.url().startsWith(origin + '/')) failures.push('External browser request'); });
    await page.goto(origin); await page.locator('#dashboard').waitFor({ state: 'visible' });
    await page.locator('#overview-review').waitFor({ state: 'visible' });
    await page.locator('#overview-review-open').click();
    const ready = () => page.locator('#request-list-status[data-state="ready"]').waitFor();
    await ready();
    const filter = key => page.locator(`[data-review-filter="${key}"]`);
    assert.equal(await filter('matched').getAttribute('aria-pressed'), 'true');
    assert.equal(await page.locator('#request-list tr[data-request-id]').count(), 2);
    assert.equal(await page.locator(`[data-request-id="${observed.id}"] .request-risk-badge`).textContent(), 'Detected match');
    await filter('blocked').click();
    assert.equal(await page.locator('#request-list tr[data-request-id]').count(), 1);
    assert.equal(await page.locator('#request-list tr').getAttribute('data-request-id'), blocked.id);
    await filter('attention').click();
    // Input blocking also leaves the output check unknown: filter counts overlap.
    assert.deepEqual((await page.locator('#request-list tr[data-request-id]').evaluateAll(rows => rows.map(row => row.dataset.requestId))).sort(), [blocked.id, failed.id].sort());
    passed.push('completed_observations_separate_from_blocked_and_unknown_outcomes');

    await filter('all').click(); await page.locator('#request-search').fill('no-such-request');
    await page.getByText('No records match these filters', { exact: true }).waitFor();
    await page.locator('#request-reset-filters').click();
    await page.locator('#request-search').fill(observed.id);
    await page.locator('#console-language').selectOption('zh-CN');
    assert.equal(await page.locator('#request-search').inputValue(), observed.id);
    assert.equal(await page.locator('#request-list tr[data-request-id]').count(), 1);
    await page.locator('#request-list .request-open').click();
    await page.locator('#request-detail').waitFor({ state: 'visible' });
    assert.match(await page.locator('#request-review-checks').textContent(), /敏感输出检测/);
    assert.match(await page.locator('#request-review-checks').textContent(), /email/);
    assert.ok(!(await page.locator('#request-detail').textContent()).includes(privateEmail));
    assert.ok(!(await page.locator('#request-detail').textContent()).includes(privatePrompt));
    await page.screenshot({ path: path.join(output, 'review-detail-zh.png'), animations: 'disabled' });
    await page.locator('#request-evidence').click();
    await page.locator('#evidence-detail').waitFor({ state: 'visible' });
    assert.match(await page.locator('#evidence-detail-fields').textContent(), new RegExp(observed.id));
    assert.equal(await page.locator('#evidence-app').inputValue(), a.application.id);
    assert.equal(await page.locator('#evidence-content').isVisible(), false);
    assert.ok(!requests.some(url => new URL(url).pathname.includes('/content')));
    await page.locator('#evidence-return-button').click();
    assert.equal(await page.locator('#request-search').inputValue(), observed.id);
    assert.equal(await page.locator('#request-list tr[data-request-id]').count(), 1);
    await page.locator('#request-list .request-open').click();
    await page.locator('#request-task').click();
    await page.locator('#evidence-task-status[data-state="ready"]').waitFor();
    assert.deepEqual(await page.locator('#evidence-task-app-options input:checked').evaluateAll(nodes => nodes.map(n => n.value)), [a.application.id]);
    assert.ok(!(await page.locator('#evidence-task-calls').textContent()).includes(normal.id));
    const taskURL = new URL(requests.filter(url => new URL(url).pathname.startsWith('/api/v1/evidence-traces/')).at(-1));
    assert.deepEqual(taskURL.searchParams.getAll('application_id'), [a.application.id]);
    await page.locator('#evidence-return-button').click();
    passed.push('localized_metadata_summary_direct_evidence_and_single_application_task_shortcut_with_return');

    await page.locator('#request-reset-filters').click();
    // Delay an older application response behind a newer selection.
    let entered;
    const seen = new Promise(resolve => { entered = resolve; });
    const held = new Promise(resolve => { releaseHeld = resolve; });
    const pattern = '**/api/v1/requests?*';
    const delayed = async route => {
      if (new URL(route.request().url()).searchParams.get('application_id') !== a.application.id) { await route.continue(); return; }
      const response = await route.fetch(); entered(); await held; await route.fulfill({ response });
    };
    await page.route(pattern, delayed);
    await page.locator('#requests-app').selectOption(a.application.id); await seen;
    await page.locator('#request-list-status[data-state="loading"]').waitFor();
    assert.equal(await page.locator('#request-list tr[data-request-id]').count(), 0);
    await page.locator('#requests-app').selectOption(b.application.id); await ready();
    const olderResponse = page.waitForResponse(response => new URL(response.url()).searchParams.get('application_id') === a.application.id);
    releaseHeld(); await page.unrouteAll({ behavior: 'wait' });
    await (await olderResponse).finished();
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.equal(await page.locator('#request-list tr[data-request-id]').count(), 1);
    assert.equal(await page.locator('#request-list tr').getAttribute('data-request-id'), normal.id);
    const unavailable = route => route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":{"code":"test_unavailable","message":"Unavailable"}}' });
    await page.route(pattern, unavailable); await page.locator('#refresh-requests').click();
    await page.locator('#request-list-status[data-state="error"]').waitFor();
    assert.equal(await page.locator('#request-list tr[data-request-id]').count(), 0);
    assert.equal(await filter('matched').locator('strong').textContent(), '—');
    await page.unroute(pattern, unavailable); await page.locator('#refresh-requests').click(); await ready();
    assert.equal(await page.locator('#request-list tr').getAttribute('data-request-id'), normal.id);
    passed.push('application_race_suppression_and_failure_without_stale_rows_or_zero_risk_claim');

    await page.locator('#requests-app').selectOption(''); await ready();
    await page.locator('#console-language').selectOption('en');
    await page.screenshot({ path: path.join(output, 'review-desktop-en.png'), fullPage: true, animations: 'disabled' });
    await page.locator('#console-language').selectOption('zh-CN');
    await page.screenshot({ path: path.join(output, 'review-desktop-zh.png'), fullPage: true, animations: 'disabled' });
    await page.setViewportSize({ width: 390, height: 844 });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    const riskBounds = await page.locator(`[data-request-id="${observed.id}"] .request-risk-badge`).boundingBox();
    assert.ok(riskBounds.x >= 0 && riskBounds.x + riskBounds.width <= 390, 'mobile risk results must not require horizontal scrolling');
    await page.screenshot({ path: path.join(output, 'review-mobile-zh.png'), fullPage: true, animations: 'disabled' });
    await page.locator('#console-language').selectOption('en');
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    await page.screenshot({ path: path.join(output, 'review-mobile-en.png'), fullPage: true, animations: 'disabled' });
    await page.locator('#console-language').selectOption('zh-CN');
    await page.locator(`[data-request-id="${observed.id}"] .request-open`).click();
    await page.screenshot({ path: path.join(output, 'review-detail-mobile-zh.png'), animations: 'disabled' });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    assert.equal(await page.locator('#request-evidence').isVisible(), true);
    await page.locator('#request-detail').press('Escape');
    const storage = await page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage } }));
    assert.equal(Object.keys(storage.session).length, 0);
    assert.deepEqual(Object.keys(storage.local), ['govweave.locale']);
    assert.ok(!JSON.stringify(storage).includes(observed.id));
    assert.equal(calls, 3, 'reviewing records/evidence must not invoke a model');
    assert.deepEqual(failures, []);
    passed.push('desktop_mobile_keyboard_locale_and_no_content_reveal_or_browser_storage');
    await fs.writeFile(path.join(output, 'summary.json'), JSON.stringify({ passed, provider_calls: calls,
      scope: 'Actual local browser, gateway and synthetic upstream. No real model, automatic content reveal or compliance verdict.' }, null, 2) + '\n', { mode: 0o600 });
    console.log(`Request review checks passed (${passed.length} groups). Screenshots: ${output}`);
  } finally {
    if (releaseHeld) releaseHeld();
    if (browser) await browser.close();
    if (child && child.exitCode === null) { child.kill('SIGTERM'); await new Promise(resolve => child.once('exit', resolve)); }
    await new Promise(resolve => provider.close(resolve));
    await fs.rm(directory, { recursive: true, force: true });
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
