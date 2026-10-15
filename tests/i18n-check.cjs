// No test dependencies. Check message coverage and locale fallback without a browser.
const fs = require('node:fs/promises');
const assert = require('node:assert/strict');
async function main() {
  const source = await fs.readFile('internal/server/web/i18n.js', 'utf8');
  const catalog = JSON.parse(source.split('const chinese = ')[1].split(';\nconst preferenceKey')[0]);
  for (const file of ['app.js', 'gateway.js', 'policies.js']) {
    const js = await fs.readFile(`internal/server/web/${file}`, 'utf8');
    assert.ok(!/[\p{Script=Han}]/u.test(js), `${file} contains untranslated source text`);
    for (const match of js.matchAll(/\bt\(("(?:\\.|[^"\\])*")/g)) {
      const key = JSON.parse(match[1]);
      assert.ok(Object.hasOwn(catalog, key), `Missing Chinese message: ${key}`);
    }
  }
  const html = await fs.readFile('internal/server/web/index.html', 'utf8');
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
