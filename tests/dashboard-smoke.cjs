const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const http = require('node:http');

async function main() {
  const root = path.resolve('internal/server/web');
  const output = path.resolve('dist/dashboard-smoke');
  await fs.mkdir(output, { recursive: true });
  const now = Date.now(), day = 86400000;
  const connections = ['Primary model', 'Reasoning model', 'Local model', 'Staging model'].map((name, index) => ({ id: `connection-${index}`, name, alias: `model-${index}`, model: `upstream-${index}`, base_url: 'https://model.example/v1', enabled: index < 3, has_credential: true, timeout_seconds: 60, revision: 1 }));
  const applications = ['Support assistant', 'Knowledge assistant', 'Document review', 'Research agent'].map((name, index) => ({ id: `app-${index}`, name, key_prefix: `gw_test_${index}`, allowed_connections: [connections[index % 3].id], revoked: false, revision: 1 }));
  const records = [];
  for (const [index, count] of [2, 8, 3, 17, 28, 11, 9].entries()) {
    for (let offset = 0; offset < count; offset++) {
      const outcome = offset % 11 === 0 ? 'blocked' : offset % 13 === 0 ? 'failed' : offset % 7 === 0 ? 'cancelled' : 'completed';
      const matched = outcome === 'blocked' || offset % 9 === 0;
      records.push({ request_id: `synthetic-${index}-${offset}`, application_id: applications[offset % 4].id, connection_id: connections[offset % 3].id, model: connections[offset % 3].alias, operation: 'chat.completions', started_at: new Date(now - (6 - index) * day - (offset + 1) * 60000).toISOString(), duration_ms: 120 + offset * 31, outcome, decision: outcome === 'blocked' ? 'deny' : 'allow', http_status: outcome === 'blocked' ? 403 : outcome === 'failed' ? 502 : 200, content_policy: { revision: 1, result: matched ? 'observe' : 'allow', matched_rules: matched ? ['api_key'] : [], ruleset_version: 'credential-v1' }, output_policy: { revision: 1, result: matched ? 'observe' : 'allow', state: 'observed', matched_categories: matched ? ['email'] : [] } });
    }
  }
  records.sort((first, second) => second.started_at.localeCompare(first.started_at));
  const fixture = { records, failRecords: false, authenticated: true, available: true };
  let origin, browser;
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, origin);
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    const json = (value, status = 200) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
    if (url.pathname === '/healthz') return json({ status: 'ok', service: 'govweave' });
    if (url.pathname === '/api/v1/auth/status') return json({ authenticated: fixture.authenticated, setup_required: false });
    if (url.pathname === '/api/v1/auth/logout') { fixture.authenticated = false; return json({}); }
    if (url.pathname === '/api/v1/instance') return json({ organization_name: 'GovWeave workspace', public_url: origin, configured: true, revision: 1, listen_addr: '127.0.0.1', sources: { organization_name: 'console', public_url: 'console' }, endpoints: {} });
    if (url.pathname === '/api/v1/gateway') return json({ connections, applications });
    if (url.pathname === '/api/v1/policies/credential-egress') return json({ revision: 1, mode: 'observe', rules: ['api_key'], application_ids: [], connection_ids: [] });
    if (url.pathname === '/api/v1/requests') {
      if (fixture.failRecords) return json({ error: { message: 'Synthetic record failure' } }, 503);
      const app = url.searchParams.get('application_id');
      return json({ available: fixture.available, records: fixture.records.filter(record => !app || record.application_id === app) });
    }
    if (url.pathname === '/api/v1/evidence/config') return json({ schema_version: 1, revision: 1, mode: 'disabled', application_ids: [], retention_days: 30, max_content_bytes: 65536 });
    const file = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
    if (!/^[a-z][a-z0-9.-]*\.(html|js|css|svg)$/.test(file)) return json({ error: { message: 'Not found' } }, 404);
    try {
      const data = await fs.readFile(path.join(root, file));
      const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };
      res.writeHead(200, { 'Content-Type': types[path.extname(file)] }); res.end(data);
    } catch { json({ error: { message: 'Not found' } }, 404); }
  });
  try {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    origin = `http://127.0.0.1:${server.address().port}`;
    browser = await chromium.launch({ executablePath: process.env.GOVWEAVE_BROWSER_PATH || '/usr/bin/google-chrome', headless: true, args: ['--no-sandbox'] });
    const context = await browser.newContext({ viewport: { width: 1600, height: 1100 }, locale: 'zh-CN' });
    const page = await context.newPage(), errors = [], external = [], badResponses = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => { if (!request.url().startsWith(origin + '/')) external.push(request.url()); });
    page.on('response', response => { if (response.status() >= 400 && !response.url().includes('/api/v1/requests')) badResponses.push(response.url()); });
    await page.goto(origin);
    await page.waitForFunction(() => document.getElementById('traffic-total').textContent === '78').catch(async error => {
      console.error({ errors, badResponses, text: (await page.locator('body').innerText()).slice(0, 6000) });
      await page.screenshot({ path: path.join(output, 'bootstrap-failure.png'), fullPage: true });
      throw error;
    });
    assert.equal(await page.locator('html').getAttribute('lang'), 'en');
    assert.equal(await page.locator('#page-title').textContent(), 'Overview');
    assert.equal(await page.locator('#metric-models').textContent(), '3');
    assert.equal(await page.locator('#metric-apps').textContent(), '4');
    assert.equal(await page.locator('.finding-row').count(), 5);
    assert.equal(await page.locator('#page-title').evaluate(element => getComputedStyle(element).fontSize), '24px');
    assert.equal(await page.locator('#metric-models').evaluate(element => getComputedStyle(element).fontSize), '32px');
    assert.equal(await page.locator('.chart-bar').count() > 0, true);
    assert.equal(await page.locator('.tabs [data-tab="applications"]>span').first().evaluate(element => element.getBoundingClientRect().height < 30), true, 'Desktop navigation labels stay on one line');
    await page.screenshot({ path: path.join(output, 'overview-en.png'), fullPage: true });
    await page.screenshot({ path: path.join(output, 'overview-en-viewport.png') });
    await page.locator('[data-traffic-period="1"]').click();
    await page.waitForFunction(() => document.getElementById('traffic-total').textContent === '9');
    await page.locator('[data-traffic-period="7"]').click();
    await page.locator('#traffic-model').selectOption('model-0');
    assert.equal(Number(await page.locator('#traffic-total').textContent()), records.filter(record => record.model === 'model-0').length);
    await page.locator('#console-language').selectOption('zh-CN');
    assert.equal(await page.locator('#traffic-model').inputValue(), 'model-0');
    assert.equal(await page.locator('#page-title').textContent(), '运行总览');
    assert.equal(await page.locator('#traffic-title').textContent(), '请求活动');
    assert.equal(await page.locator('#review-title').textContent(), '待复核列表');
    await page.locator('#traffic-model').selectOption('');
    await page.screenshot({ path: path.join(output, 'overview-zh.png'), fullPage: true });
    await page.screenshot({ path: path.join(output, 'overview-zh-viewport.png') });
    await page.reload();
    await page.waitForFunction(() => document.getElementById('traffic-total').textContent === '78');
    assert.equal(await page.locator('html').getAttribute('lang'), 'zh-CN');
    await page.locator('#console-language').selectOption('en');
    await page.locator('#dashboard-new-application').click();
    assert.equal(await page.locator('#application-editor').evaluate(element => element.open), true);
    await page.locator('#application-name').fill('Untranslated application');
    await page.keyboard.press('Escape');
    await page.locator('.finding-row button').first().click();
    assert.equal(await page.locator('#request-detail').evaluate(element => element.open), true);
    await page.keyboard.press('Escape');
    await page.keyboard.press('Control+k');
    assert.equal(await page.locator('#console-search').evaluate(element => element === document.activeElement), true);
    await page.locator('#console-search').fill('Knowledge assistant');
    await page.locator('#console-search').press('Enter');
    await page.waitForFunction(() => !document.getElementById('page-requests').hidden && document.getElementById('request-list').querySelectorAll('tr').length > 0);
    assert.equal(await page.locator('#request-search').inputValue(), 'Knowledge assistant');
    assert.equal(await page.locator('#dashboard-new-application').isVisible(), false);
    await page.locator('.tabs [data-tab="overview"]').click();
    await page.waitForFunction(() => document.getElementById('traffic-total').textContent === '78');
    await page.locator('#toggle-sidebar').click();
    assert.equal(await page.locator('#console-sidebar').isVisible(), false);
    await page.locator('#toggle-sidebar').click();
    assert.equal(await page.locator('#console-sidebar').isVisible(), true);
    for (const locale of ['en', 'zh-CN']) {
      await page.locator('#console-language').selectOption(locale);
      for (const width of [1440, 1024, 768, 390, 360]) {
        await page.setViewportSize({ width, height: 1000 });
        const dimensions = await page.evaluate(() => ({ viewport: innerWidth, content: document.documentElement.scrollWidth }));
        assert.ok(dimensions.content <= dimensions.viewport, `${locale} ${width}px layout overflows: ${JSON.stringify(dimensions)}`);
      }
      await page.setViewportSize({ width: 390, height: 844 });
      assert.ok(await page.locator('#console-search').evaluate(element => element.getBoundingClientRect().width > 70), 'Mobile search remains usable');
      await page.waitForFunction(() => Number(document.querySelector('#traffic-chart svg').getAttribute('viewBox').split(' ')[2]) < 400);
      await page.screenshot({ path: path.join(output, `overview-mobile-${locale}.png`), fullPage: true });
      await page.screenshot({ path: path.join(output, `overview-mobile-${locale}-viewport.png`) });
    }
    await page.setViewportSize({ width: 1600, height: 1100 });
    await page.locator('#console-language').selectOption('en');
    fixture.records = [];
    await page.locator('#refresh-overview').click();
    await page.waitForFunction(() => document.getElementById('traffic-total').textContent === '0');
    assert.equal(await page.locator('.finding-row').count(), 0);
    assert.match(await page.locator('#traffic-chart').textContent(), /No recorded calls/);
    await page.screenshot({ path: path.join(output, 'overview-empty.png'), fullPage: true });
    fixture.failRecords = true;
    await page.locator('#refresh-overview').click();
    await page.waitForFunction(() => document.getElementById('traffic-total').textContent === '—');
    assert.equal(await page.locator('#metric-matches').textContent(), '—');
    assert.match(await page.locator('#traffic-chart').textContent(), /unavailable/);
    assert.equal(await page.locator('.chart-bar').count(), 0);
    await page.locator('#console-language').selectOption('zh-CN');
    assert.match(await page.locator('#traffic-chart').textContent(), /调用记录不可用/);
    fixture.failRecords = false; fixture.records = records; fixture.available = false;
    await page.locator('#refresh-overview').click();
    await page.waitForFunction(() => document.getElementById('traffic-total').textContent === '78');
    assert.match(await page.locator('#traffic-status').textContent(), /记录不可用/);
    await page.locator('#logout').click();
    await page.waitForFunction(() => document.body.dataset.authenticated === 'false');
    assert.equal(await page.locator('#traffic-total').textContent(), '—');
    assert.equal(await page.locator('.chart-bar').count(), 0);
    assert.equal(await page.locator('.finding-row').count(), 0);
    assert.deepEqual(errors, []);
    assert.deepEqual(external, []);
    assert.deepEqual(badResponses, []);
    console.log(`Dashboard browser checks passed using synthetic API fixtures, not a running Go backend. Screenshots: ${output}`);
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
