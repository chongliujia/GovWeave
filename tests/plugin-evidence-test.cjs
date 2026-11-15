const fs = require('node:fs/promises');
const assert = require('node:assert/strict');
async function main() {
  const source = (await fs.readFile('internal/server/web/plugin-evidence.js', 'utf8')).replace('import { t } from "/i18n.js";', 'const t = key => key;');
  const { collectEvidenceFields, parseEvidenceDraft } = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
  const pack = { controls: [{ title: 'Test', applies_when: { all: [{ fact: 'scope.test', source: 'assessment', value: true }] }, requirement: { any: [{ fact: 'document.test', source: 'document', value: false }, { not: { fact: 'testing.test', source: 'assessment', value: true } }, { fact: 'scope.test', source: 'assessment', value: true }] } }] };
  const fields = collectEvidenceFields(pack);
  assert.equal(fields.length, 3);
  assert.equal(fields.find(f => f.key === 'testing.test').automatic, true);
  const raw = { present: true, type: 'boolean', value: 'false', source: 'document', evidence_id: 'review-1', observed_at: '2026-11-15T08:00:00Z', expires_at: '' };
  assert.equal(parseEvidenceDraft('document.test', raw).value, false);
  assert.equal(parseEvidenceDraft('document.test', { ...raw, present: false }), null);
  assert.equal(parseEvidenceDraft('document.test', { ...raw, type: 'number', value: '0' }).value, 0);
  assert.equal(parseEvidenceDraft('document.test', { ...raw, type: 'string', value: '<script>untrusted</script>' }).value, '<script>untrusted</script>');
  for (const patch of [{ value: '' }, { type: 'number', value: '' }, { type: 'number', value: 'Infinity' }, { type: 'string', value: 'x'.repeat(513) }, { evidence_id: 'a b' }, { source: 'runtime' }, { observed_at: '2026-11-15' }, { expires_at: '2026-11-14T08:00:00Z' }]) assert.throws(() => parseEvidenceDraft('document.test', { ...raw, ...patch }));
  for (const key of ['runtime.fake', 'testing.fake']) assert.throws(() => parseEvidenceDraft(key, raw));
  console.log('Evidence checks passed: nested requirements, absent/false distinction, source boundaries and bounded provenance.');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
