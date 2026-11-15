// No test dependencies. Check message coverage and locale fallback without a browser.
const fs = require('node:fs/promises');
const assert = require('node:assert/strict');
async function main() {
  const source = await fs.readFile('internal/server/web/i18n.js', 'utf8');
  const catalog = JSON.parse(source.split('const chinese = ')[1].split(';\nconst preferenceKey')[0]);
  const keys = [...source.split(';\nconst preferenceKey')[0].matchAll(/^  ("(?:\\.|[^"\\])*"):/gm)].map(match => JSON.parse(match[1]));
  assert.equal(new Set(keys).size, keys.length, 'Translation keys must not silently override each other');
  for (const file of ['app.js', 'gateway.js', 'dashboard.js', 'request-review.js', 'task-map.js', 'task-map-view.js', 'integration.js', 'evidence.js', 'policies.js', 'plugins.js', 'plugin-assessment.js', 'plugin-tests.js', 'plugin-coverage.js', 'plugin-remediation.js', 'plugin-evidence.js']) {
    const js = await fs.readFile(`internal/server/web/${file}`, 'utf8');
    assert.ok(!/[\p{Script=Han}]/u.test(js), `${file} contains untranslated source text`);
    for (const match of js.matchAll(/\bt\(("(?:\\.|[^"\\])*")/g)) {
      const key = JSON.parse(match[1]);
      assert.ok(Object.hasOwn(catalog, key), `Missing Chinese message: ${key}`);
    }
  }
  const html = await fs.readFile('internal/server/web/index.html', 'utf8');
  const plugins = await fs.readFile('internal/server/web/plugins.js', 'utf8');
  const assessment = await fs.readFile('internal/server/web/plugin-assessment.js', 'utf8');
  for (const match of assessment.matchAll(/"(?:\\.|[^"\\\n])*"/g)) {
    const key = JSON.parse(match[0]);
    if (/^[A-Z].*\s/.test(key)) assert.ok(Object.hasOwn(catalog, key), `Missing assessment message: ${key}`);
  }
  const remediation = await fs.readFile('internal/server/web/plugin-remediation.js', 'utf8');
  for (const match of remediation.matchAll(/"(?:\\.|[^"\\\n])*"/g)) {
    const key = JSON.parse(match[0]);
    if (/^[A-Z].*\s/.test(key)) assert.ok(Object.hasOwn(catalog, key), `Missing remediation message: ${key}`);
  }
  for (const match of plugins.matchAll(/previewMessage = ("(?:\\.|[^"\\])+")/g)) {
    assert.ok(Object.hasOwn(catalog, JSON.parse(match[1])), `Missing preview status: ${match[1]}`);
  }
  for (const match of plugins.matchAll(/(?:label\("[^"\n]+",\s*|(?:field|button)\([^,\n]+,\s*|(?:section|step|disclosure)\()("(?:\\.|[^"\\])*")/g)) {
    const key = JSON.parse(match[1]);
    assert.ok(Object.hasOwn(catalog, key), `Missing plugin label: ${key}`);
  }
  for (const name of ['modes', 'modeHints', 'detectorNames', 'categories', 'reviews', 'frameworks', 'assessments', 'previewResults', 'previewReasons']) {
    const values = plugins.match(new RegExp(`const ${name} = \\{([^\\n]+)\\};`))[1];
    for (const match of values.matchAll(/:\s*("(?:\\.|[^"\\])*")/g)) {
      assert.ok(Object.hasOwn(catalog, JSON.parse(match[1])), `Missing plugin enum: ${match[1]}`);
    }
  }
  assert.match(html, /<html lang="en">/);
  // Only the Chinese language picker labels are Chinese in default markup.
  assert.ok(!/[\p{Script=Han}]/u.test(html.replaceAll('简体中文', '').replaceAll('语言', '')));
  global.document = { documentElement: {}, querySelectorAll: () => [] };
  global.localStorage = { setItem() { throw new Error('storage blocked'); } };
  const i18n = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
  assert.equal(i18n.getLocale(), 'en');
  assert.equal(i18n.t('Overview'), 'Overview');
  i18n.setLocale('zh-CN');
  assert.equal(i18n.t('Overview'), '运行总览');
  assert.equal(i18n.t('Edit: {name}', { name: '<script>企业模型</script>' }), '编辑：<script>企业模型</script>');
  assert.equal(i18n.t('unknown_message'), 'unknown_message');
  i18n.setLocale('invalid');
  assert.equal(i18n.getLocale(), 'en');
  assert.equal(i18n.t('Edit: {name}', { name: '中文名称' }), 'Edit: 中文名称');
  console.log('Locale checks passed: literal coverage, English markup, interpolation, unsupported locale and blocked storage fallback.');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
