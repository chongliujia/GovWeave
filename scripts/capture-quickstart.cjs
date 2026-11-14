// Capture the actual console of demo-quickstart.py's disposable synthetic session.
// The session cookie arrives over stdin and is never written to disk.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');

const captions = {
  en: [
    ['Protect one application', 'Saved output policy: redact · sensitive-text-v1 · synthetic local model'],
    ['Three requests. Three recorded outcomes.', 'Normal answer: 200 · Email redacted: 200 · Credential input blocked: 403'],
    ['Inspect the redaction decision', 'The request record links the detector, policy revision and retained evidence.'],
    ['Review the original model output', 'Explicit content capture is enabled for this demo; original text access is audited.'],
    ['Compare the output prepared for the app', 'The synthetic email is replaced with [REDACTED]. The original is kept separately.'],
    ['Block a credential before model access', 'The third request is refused before upstream I/O. Try all three cases locally.'],
  ],
  'zh-CN': [
    ['为一个应用开启输出保护', '已保存策略：脱敏 · sensitive-text-v1 · 本机合成模型'],
    ['三次请求，三种结果', '普通回答 200 · 邮箱脱敏 200 · 含凭证的输入被拦截 403'],
    ['查看这次脱敏的决策依据', '调用记录关联检测器、策略修订和独立留存的证据。'],
    ['复核模型的原始输出', '本演示已显式开启正文采集；查看原文会留下访问审计。'],
    ['对比准备交付给应用的输出', '合成邮箱已替换为 [REDACTED]，原始输出独立保存。'],
    ['在访问模型前拦截凭证', '第三次请求没有访问上游。运行下方命令，亲自验证这三个场景。'],
  ],
};

async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  const session = JSON.parse(input);
  const origin = new URL(session.origin);
  assert.equal(origin.hostname, '127.0.0.1');
  assert.equal(origin.protocol, 'http:');
  assert.equal(origin.pathname, '/');
  const output = path.resolve(process.argv[2]);
  const browser = await chromium.launch({
    executablePath: process.env.GOVWEAVE_BROWSER_PATH || '/usr/bin/google-chrome',
    headless: true, args: ['--no-sandbox'],
  });
  try {
    const context = await browser.newContext({ viewport: { width: 1280, height: 760 }, deviceScaleFactor: 1 });
    await context.addCookies(session.cookies);
    const failures = [];
    await context.route('**/*', route => {
      if (route.request().url().startsWith(session.origin + '/')) return route.continue();
      failures.push('Unexpected external request');
      return route.abort();
    });
    const page = await context.newPage();
    page.on('pageerror', () => failures.push('Console JavaScript error'));
    const art = await browser.newPage({ viewport: { width: 1120, height: 856 }, deviceScaleFactor: 1 });
    const escape = text => text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
    async function frame(language, index) {
      await page.evaluate(() => document.fonts.ready);
      const visible = await page.locator('body').innerText();
      assert.ok(session.cookies.every(cookie => !visible.includes(cookie.value)), 'Session cookie appeared in UI');
      const screenshot = await page.screenshot({ animations: 'disabled' });
      const [title, description] = captions[language][index];
      const zh = language === 'zh-CN';
      const comparison = index === 3 ? 'Synthetic email: demo.person@example.com' : index === 4 ? 'Synthetic email: [REDACTED]' : '';
      // This caption frame is outside the product. The screenshot itself is unchanged.
      await art.setContent(`<!doctype html><html lang="${language}"><meta charset="utf-8"><style>
        *{box-sizing:border-box}body{margin:0;background:#0e252d;color:#fff;font-family:Arial,'Noto Sans CJK SC',sans-serif}
        header{height:${comparison ? 180 : 132}px;padding:19px 30px} .brand{display:flex;justify-content:space-between;color:#9ce9d0;font-size:13px;letter-spacing:1.3px}
        h1{font-size:32px;line-height:1.2;margin:13px 0 7px;letter-spacing:-.6px}p{font-size:15px;margin:0;color:#d2e0e3}
        .comparison{display:block;font-size:24px;color:#acedd5;margin-top:12px;letter-spacing:0}
        img{display:block;width:1120px;height:${comparison ? 617 : 665}px;object-fit:contain;background:#fff}
        footer{height:59px;display:flex;align-items:center;justify-content:space-between;padding:0 30px;font-size:12px;color:#a4bfc6}
        code{font-size:15px;color:#acedd5}strong{color:white;font-weight:500}
      </style><header><div class="brand"><strong>GovWeave</strong><span>${zh ? '真实控制台 · 合成数据 · 分步演示' : 'ACTUAL CONSOLE · SYNTHETIC DATA · GUIDED WALKTHROUGH'} &nbsp; ${index + 1}/6</span></div>
      <h1>${escape(title)}</h1><p>${escape(description)}</p>${comparison ? `<code class="comparison">${escape(comparison)}</code>` : ''}</header>
      <img alt="Actual GovWeave console" src="data:image/png;base64,${screenshot.toString('base64')}">
      <footer><span>${zh ? '本机脚本模型 · 预览版 · 非合规认证' : 'Local scripted model · Preview · No compliance certification'}</span><code>make demo-quickstart${zh ? ' DEMO_LANG=zh-CN' : ''}</code></footer></html>`);
      await art.locator('img').evaluate(image => image.decode());
      await art.evaluate(() => document.fonts.ready);
      assert.ok(await art.evaluate(() => document.documentElement.scrollWidth === 1120 && document.documentElement.scrollHeight === 856));
      await art.screenshot({ path: path.join(output, `${language}-${String(index + 1).padStart(2, '0')}.png`) });
    }
    const redacted = session.stages.find(stage => stage.scenario === 'email');
    const blocked = session.stages.find(stage => stage.scenario === 'credential');
    const response = await context.request.get(`${session.origin}/api/v1/evidence/${redacted.evidence_id}?application_id=${session.application_id}`);
    assert.equal(response.status(), 200);
    const detail = await response.json();
    const original = detail.objects.find(item => item.kind === 'upstream_output');
    const released = detail.objects.find(item => item.kind === 'released_output');
    for (const language of ['en', 'zh-CN']) {
      await page.goto(session.origin);
      await page.locator('#dashboard').waitFor({ state: 'visible' });
      await page.locator('#console-language').selectOption(language);
      await page.locator('[data-tab="plugins"]').first().click();
      await page.locator('#plugin-tab-output').click();
      await page.waitForFunction(() => !document.getElementById('plugin-output-fields').disabled);
      assert.equal(await page.locator('#plugin-mode').inputValue(), 'redact');
      assert.equal(await page.locator('#plugin-detector').inputValue(), 'sensitive-text-v1');
      await page.locator('#plugin-mode-choices').scrollIntoViewIfNeeded();
      await frame(language, 0);

      await page.locator('[data-tab="requests"]').first().click();
      await page.locator('#request-list-status[data-state="ready"]').waitFor();
      assert.equal(await page.locator('#request-list tr[data-request-id]').count(), 3);
      await page.locator('#request-list').scrollIntoViewIfNeeded();
      await frame(language, 1);
      await page.locator(`[data-request-id="${redacted.request_id}"] .request-open`).click();
      await page.locator('#request-detail').waitFor({ state: 'visible' });
      assert.match(await page.locator('#request-review-checks').innerText(), /sensitive-text-v1/);
      await frame(language, 2);

      await page.locator('#request-evidence').click();
      await page.locator('#evidence-detail').waitFor({ state: 'visible' });
      await page.locator(`[data-evidence-reveal="redacted"][data-object-id="${original.id}"]`).click();
      await page.locator('#evidence-content[data-state="redacted"]').waitFor();
      await page.locator(`[data-evidence-reveal="raw"][data-object-id="${original.id}"]`).click();
      await page.locator('#evidence-content[data-state="raw"]').waitFor();
      assert.match(await page.locator('#evidence-content-text').innerText(), /demo.person@example.com/);
      await page.locator('#evidence-content').scrollIntoViewIfNeeded();
      await frame(language, 3);

      await page.locator(`[data-evidence-reveal="redacted"][data-object-id="${released.id}"]`).click();
      await page.locator('#evidence-content[data-state="redacted"]').waitFor();
      await page.locator(`[data-evidence-reveal="raw"][data-object-id="${released.id}"]`).click();
      await page.locator('#evidence-content[data-state="raw"]').waitFor();
      assert.match(await page.locator('#evidence-content-text').innerText(), /\[REDACTED\]/);
      assert.ok(!(await page.locator('#evidence-content-text').innerText()).includes('demo.person@example.com'));
      await page.locator('#evidence-content').scrollIntoViewIfNeeded();
      await frame(language, 4);

      await page.locator('[data-tab="requests"]').first().click();
      await page.locator('#request-list-status[data-state="ready"]').waitFor();
      await page.locator(`[data-request-id="${blocked.request_id}"] .request-open`).click();
      await page.locator('#request-detail').waitFor({ state: 'visible' });
      await frame(language, 5);
      await page.locator('#request-detail').press('Escape');
    }
    const accessResponse = await context.request.get(session.origin + '/api/v1/evidence/access');
    assert.equal(accessResponse.status(), 200);
    const accesses = await accessResponse.json();
    assert.equal(accesses.items.filter(item => item.action === 'reveal_authorized').length, 8);
    assert.deepEqual(failures, []);
    console.log('Captured 6 real-console scenes in each language; content access auditing verified.');
  } finally {
    await browser.close();
  }
}
main().catch(error => { console.error(`Walkthrough capture failed: ${error.message}`); process.exitCode = 1; });
