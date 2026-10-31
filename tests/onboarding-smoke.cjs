// Optional actual-browser onboarding test. Only isolated loopback fixtures are used.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawn } = require('node:child_process');

async function main() {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'govweave-onboarding-'));
  const output = path.resolve('dist/onboarding-smoke', new Date().toISOString().replace(/[:.]/g, '-'));
  await fs.mkdir(output, { recursive: true, mode: 0o700 });
  const providerKey = 'synthetic-onboarding-provider-key';
  const answer = 'Synthetic onboarding response, excluded from the console.';
  const privateEmail = 'private-onboarding-contact@internal.example';
  const password = 'synthetic onboarding administrator password';
  let calls = 0, mode = 'normal', entered, release, browser, child;
  const payloads = [], requests = [], failures = [], passed = [];
  const upstream = http.createServer(async (req, res) => {
    assert.equal(req.headers.authorization, `Bearer ${providerKey}`);
    assert.equal(req.headers['x-govweave-trace-id'], undefined);
    assert.equal(req.headers.cookie, undefined);
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/v1/models') { res.end(JSON.stringify({ data: [{ id: 'fixture-alpha' }, { id: 'fixture-beta' }] })); return; }
    assert.equal(req.url, '/v1/chat/completions');
    calls++;
    let raw = ''; for await (const chunk of req) raw += chunk;
    const payload = JSON.parse(raw); payloads.push(payload);
    assert.equal(payload.stream, false);
    if (mode === 'hold') {
      const barrier = new Promise(resolve => { release = resolve; });
      entered();
      await barrier;
    }
    if (mode === 'malformed') { res.end('{}'); return; }
    if (mode === 'incomplete') { res.end('{"choices":[]}'); return; }
    res.end(JSON.stringify({ id: 'chat_local', object: 'chat.completion', created: 1, model: payload.model,
      choices: [{ index: 0, message: { role: 'assistant', content: mode === 'sensitive' ? privateEmail : answer,
        function_call: null, tool_calls: calls % 2 === 0 ? [] : null }, finish_reason: 'stop' }] }));
  });
  await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
  const reserve = http.createServer();
  await new Promise(resolve => reserve.listen(0, '127.0.0.1', resolve));
  const port = reserve.address().port;
  await new Promise(resolve => reserve.close(resolve));
  const origin = `http://127.0.0.1:${port}`;
  const upstreamURL = `http://127.0.0.1:${upstream.address().port}/v1`;
  try {
    const env = { ...process.env, GOVWEAVE_LISTEN_ADDR: `127.0.0.1:${port}`, GOVWEAVE_DATA_DIR: directory };
    for (const key of ['GOVWEAVE_PUBLIC_URL', 'GOVWEAVE_ORGANIZATION_NAME', 'GOVWEAVE_ADMIN_TOKEN_FILE']) delete env[key];
    child = spawn(path.resolve(process.env.GOVWEAVE_TEST_BINARY || 'bin/govweave'), [], { env, stdio: 'ignore' });
    for (let attempt = 0; attempt < 100; attempt++) {
      if (child.exitCode !== null) throw new Error('Isolated gateway exited during startup');
      try { if ((await fetch(origin + '/healthz')).ok) break; } catch {}
      if (attempt === 99) throw new Error('Isolated gateway did not start');
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    browser = await chromium.launch({ executablePath: process.env.GOVWEAVE_BROWSER_PATH || '/usr/bin/google-chrome', headless: true, args: ['--no-sandbox'] });
    const context = await browser.newContext({ viewport: { width: 1440, height: 1050 } });
    async function api(route, data, method = 'POST') {
      const response = await context.request.fetch(origin + route, { method, data,
        headers: { 'Content-Type': 'application/json', 'X-GovWeave-Request': 'console', Origin: origin } });
      assert.equal(response.ok(), true, `${method} ${route}: HTTP ${response.status()}`);
      return response.json();
    }
    await api('/api/v1/auth/setup', { password });
    const instance = await api('/api/v1/instance', undefined, 'GET');
    await api('/api/v1/instance', { schema_version: 1, revision: instance.revision,
      organization_name: 'Onboarding fixture', public_url: 'https://published-gateway.example' }, 'PUT');
    const connections = [];
    for (const name of ['alpha', 'beta']) {
      const snapshot = await api('/api/v1/gateway', undefined, 'GET');
      connections.push(await api('/api/v1/connections', { revision: snapshot.revision, name: `Fixture ${name}`,
        base_url: upstreamURL, model: `fixture-${name}`, alias: `${name}-alias`, api_key: providerKey,
        enabled: true, allow_insecure_http: true, timeout_seconds: 2 }));
    }
    async function createApp(name) {
      const snapshot = await api('/api/v1/gateway', undefined, 'GET');
      return api('/api/v1/applications', { revision: snapshot.revision, name, allowed_connections: connections.map(c => c.id) });
    }
    const a = await createApp('Application A'), b = await createApp('Application B');
    const page = await context.newPage();
    page.on('pageerror', error => failures.push(error.message));
    page.on('request', request => {
      requests.push(request);
      if (!request.url().startsWith(origin + '/')) failures.push('Unexpected external browser request');
    });
    await page.goto(origin);
    await page.locator('#dashboard').waitFor({ state: 'visible' });
    await page.locator('#metric-apps').filter({ hasText: '02' }).waitFor();
    await page.locator('.tabs [data-tab="deployment"]').click();
    await page.locator('#example-app').selectOption(a.application.id);
    await page.locator('#example-model').selectOption('beta-alias');
    await page.locator('#sdk-example').filter({ hasText: 'beta-alias' }).waitFor();
    assert.match(await page.locator('#sdk-example').textContent(), /stream=False/);
    assert.match(await page.locator('#sdk-example').textContent(), /published-gateway\.example/);
    await page.locator('#example-language').selectOption('curl');
    assert.match(await page.locator('#sdk-example').textContent(), /curl/);
    assert.match(await page.locator('#sdk-example').textContent(), /"stream":\s*false/);
    await page.locator('#example-language').selectOption('python');
    assert.equal(calls, 0);
    passed.push('explicit_model_and_nonstreaming_examples_without_automatic_inference');

    const state = async value => {
      try {
        await page.waitForFunction(expected => document.getElementById('integration-result').dataset.state === expected, value);
      } catch {
        throw new Error(`After ${passed.length} groups: expected ${value}, observed ${await page.locator('#integration-result').getAttribute('data-state')}: ${await page.locator('#integration-status').textContent()}`);
      }
    };
    async function operate(key, button, expected) {
      await page.locator('#integration-key').fill(key);
      await page.locator(button).click();
      await state(expected);
      assert.equal(await page.locator('#integration-key').inputValue(), '');
      assert.equal(await page.locator('#dashboard').isVisible(), true);
    }
    const checkResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/v1/integration/check');
    await operate(a.api_key, '#integration-check', 'configured');
    const preflight = await (await checkResponse).json();
    assert.equal(calls, 0);
    passed.push('configuration_check_has_no_provider_io');
    await operate(b.api_key, '#integration-send', 'failed');
    assert.equal(calls, 0);
    passed.push('wrong_application_key_stops_before_inference');
    await operate('gw_app_' + 'X'.repeat(43), '#integration-check', 'failed');
    assert.equal(calls, 0);
    passed.push('invalid_key_preserves_admin_session');

    await operate(a.api_key, '#integration-send', 'completed');
    assert.equal(calls, 1);
    assert.equal(payloads[0].model, 'fixture-beta');
    assert.match(await page.locator('#integration-result').textContent(), /req_[A-Za-z0-9_-]{22}/);
    assert.match(await page.locator('#integration-result').textContent(), /[0-9a-f]{32}/);
    assert.ok(!(await page.locator('#integration-result').textContent()).includes(answer));
    await page.locator('#integration-records').click();
    await page.locator('#page-requests').waitFor({ state: 'visible' });
    await page.locator('#request-list').getByText('Completed · 200', { exact: true }).first().waitFor();
    if (await page.locator('#request-detail').isVisible()) await page.locator('#request-detail').press('Escape');
    await page.locator('.tabs [data-tab="deployment"]').click();
    passed.push('single_inference_correlated_with_actual_audit_and_request_logs');

    mode = 'incomplete';
    await operate(a.api_key, '#integration-send', 'unknown');
    assert.equal(calls, 2);
    assert.match(await page.locator('#integration-fields').textContent(), /200/);
    mode = 'malformed';
    await operate(a.api_key, '#integration-send', 'failed');
    assert.equal(calls, 3);
    assert.match(await page.locator('#integration-fields').textContent(), /502/);
    mode = 'normal';
    passed.push('incomplete_200_remains_unknown_and_invalid_provider_response_fails');

    await page.route('**/api/v1/traces/*', route => route.fulfill({ status: 404, contentType: 'application/json',
      body: JSON.stringify({ error: { code: 'trace_not_found', message: 'Synthetic unavailable audit view' } }) }));
    await operate(a.api_key, '#integration-send', 'unknown');
    assert.equal(calls, 4);
    await page.unroute('**/api/v1/traces/*');
    passed.push('missing_audit_does_not_claim_success');

    const policy = await api('/api/v1/policies/sensitive-output', undefined, 'GET');
    const protectedPolicy = await api('/api/v1/policies/sensitive-output', { revision: policy.revision, mode: 'block',
      detector_version: 'sensitive-text-v1', categories: ['email'], application_ids: [a.application.id] }, 'PUT');
    mode = 'sensitive';
    await operate(a.api_key, '#integration-send', 'blocked');
    assert.equal(calls, 5);
    assert.ok(!(await page.locator('#integration-result').textContent()).includes(privateEmail));
    mode = 'normal';
    await api('/api/v1/policies/sensitive-output', { revision: protectedPolicy.revision, mode: 'disabled',
      detector_version: 'sensitive-text-v1', categories: ['email'], application_ids: [a.application.id] }, 'PUT');
    passed.push('enabled_output_protection_uses_nonstreaming_and_preserves_block');

    mode = 'hold';
    const entry = new Promise(resolve => { entered = resolve; });
    await page.locator('#integration-key').fill(a.api_key);
    await page.locator('#integration-send').click();
    await entry;
    await page.locator('#example-app').selectOption(b.application.id);
    await state('idle');
    assert.equal(await page.locator('#integration-key').inputValue(), '');
    mode = 'normal'; release(); release = null;
    await new Promise(resolve => setTimeout(resolve, 100));
    await state('idle');
    assert.equal(calls, 6);
    await operate(b.api_key, '#integration-check', 'configured');
    passed.push('selection_change_cancels_and_discards_late_results');

    await page.locator('#integration-key').fill(b.api_key);
    await page.locator('.tabs [data-tab="overview"]').click();
    assert.equal(await page.locator('#integration-key').inputValue(), '');
    await page.locator('.tabs [data-tab="deployment"]').click();
    await page.locator('#example-app').selectOption(a.application.id);
    await page.locator('#example-model').selectOption('beta-alias');
    await operate(a.api_key, '#integration-send', 'completed');
    assert.equal(calls, 7);
    await page.locator('#console-language').selectOption('zh-CN');
    await state('completed');
    assert.equal(await page.locator('#integration-key').inputValue(), '');
    await page.screenshot({ path: path.join(output, 'onboarding-zh.png'), fullPage: true, animations: 'disabled' });
    await page.setViewportSize({ width: 390, height: 844 });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    await page.screenshot({ path: path.join(output, 'onboarding-mobile-zh.png'), fullPage: true, animations: 'disabled' });
    await page.locator('#console-language').selectOption('en');
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    passed.push('bilingual_mobile_and_page_leave_clear_key');

    const stored = await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }));
    const audit = await fs.readFile(path.join(directory, 'calls.jsonl'), 'utf8');
    const pageText = await page.locator('body').textContent();
    for (const privateValue of [a.api_key, b.api_key, providerKey, answer, privateEmail]) {
      assert.ok(!stored.includes(privateValue) && !audit.includes(privateValue) && !pageText.includes(privateValue));
    }
    for (const request of requests.filter(r => new URL(r.url()).pathname.startsWith('/v1/'))) {
      const headers = await request.allHeaders();
      assert.equal(headers.cookie, undefined);
      assert.ok(headers.authorization?.startsWith('Bearer gw_app_'));
    }
    await page.locator('#integration-key').fill(a.api_key);
    await page.locator('#logout').click();
    await page.locator('#login-panel').waitFor({ state: 'visible' });
    assert.equal(await page.locator('#integration-key').inputValue(), '');
    passed.push('no_secret_storage_no_raw_output_no_external_requests_logout_clear');
    assert.deepEqual(failures, []);
    await fs.writeFile(path.join(output, 'configuration-check.json'), JSON.stringify(preflight, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    await fs.writeFile(path.join(output, 'summary.json'), JSON.stringify({ passed, provider_calls: calls, external_browser_requests: 0,
      scope: 'Actual local browser and gateway with synthetic model responses; Docker daemon and real providers not exercised.' }, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    console.log(`Onboarding browser checks passed (${passed.length} groups, ${calls} explicit model calls). Screenshots: ${output}`);
  } finally {
    if (release) release();
    if (browser) await browser.close();
    if (child && child.exitCode === null) {
      const stopped = new Promise(resolve => child.once('exit', resolve));
      child.kill('SIGTERM');
      const timer = setTimeout(() => child.kill('SIGKILL'), 6000);
      await stopped; clearTimeout(timer);
    }
    upstream.closeAllConnections();
    await new Promise(resolve => upstream.close(resolve));
    await fs.rm(directory, { recursive: true, force: true });
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
