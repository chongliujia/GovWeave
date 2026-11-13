const fs = require('node:fs/promises');
const assert = require('node:assert/strict');

async function main() {
  const source = (await fs.readFile('internal/server/web/plugin-assessment.js', 'utf8')).replace('import { t, formatDateTime } from "/i18n.js";', 'const t = value => value, formatDateTime = value => value;');
  const { assessmentMatches, summarizeControls, safeSourceURL } = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
  const product = { id: 'product-1', revision: 2, version: '1.0', pack_id: 'pack', pack_version: '2.0' };
  const pack = { id: 'pack', version: '2.0', sha256: 'synthetic-fingerprint' };
  const report = { product_id: product.id, product_revision: 2, state: 'ready', evaluation: { product_id: product.id, product_version: '1.0', pack_id: 'pack', pack_version: '2.0', pack_sha256: pack.sha256 } };
  assert.equal(assessmentMatches(report, product, pack), true);
  assert.equal(assessmentMatches(report, null, pack), false);
  assert.equal(assessmentMatches(report, product, null), false);
  for (const [key, value] of Object.entries({ product_id: 'another', product_version: 'old', pack_id: 'another', pack_version: 'old', pack_sha256: 'changed' })) {
    assert.equal(assessmentMatches({ ...report, evaluation: { ...report.evaluation, [key]: value } }, product, pack), false, key);
  }
  assert.equal(assessmentMatches({ ...report, product_revision: 1 }, product, pack), false);
  assert.equal(assessmentMatches({ ...report, product_id: 'another' }, product, pack), false);
  assert.equal(assessmentMatches({ ...report, state: 'pending' }, product, pack), false, 'pending cannot carry an old success');
  assert.equal(assessmentMatches({ ...report, state: 'pending', evaluation: undefined }, product, pack), true);
  assert.deepEqual(summarizeControls(['pass', 'fail', 'unknown', 'not_applicable', 'unexpected'].map(status => ({ status }))), { pass: 1, fail: 1, unknown: 2, not_applicable: 1 });
  assert.deepEqual(summarizeControls([]), { pass: 0, fail: 0, unknown: 0, not_applicable: 0 });
  for (const url of ['javascript:alert(1)', 'data:text/html,test', '//example.com', 'https://user:pass@example.com', '/local', 'bad']) assert.equal(safeSourceURL(url), null);
  assert.equal(safeSourceURL('https://example.test/reference'), 'https://example.test/reference');
  console.log('Assessment checks passed: revision/version/fingerprint binding, pending isolation, conservative counts and safe source links.');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
