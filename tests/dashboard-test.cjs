const assert = require('node:assert/strict');
const fs = require('node:fs/promises');

async function main() {
  const moduleURL = source => `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`;
  const locale = moduleURL(await fs.readFile('internal/server/web/i18n.js', 'utf8'));
  const review = moduleURL(await fs.readFile('internal/server/web/request-review.js', 'utf8'));
  const source = (await fs.readFile('internal/server/web/dashboard.js', 'utf8')).replace('/i18n.js', locale).replace('/request-review.js', review);
  const { summarizeActivity, selectReviewRecords } = await import(moduleURL(source));
  const now = Date.parse('2026-11-13T12:00:00Z');
  const record = (requestID, outcome, startedAt = '2026-11-13T11:00:00Z', model = 'model-a') => ({ request_id: requestID, outcome, started_at: startedAt, model });
  const records = [record('complete', 'completed'), record('blocked', 'blocked'), record('rejected', 'rejected'), record('failed', 'failed'), record('cancelled', 'cancelled'), record('unknown', 'incomplete'), record('future-outcome', 'new_outcome')];
  const summary = summarizeActivity(records, { now });
  assert.equal(summary.total, 7);
  assert.deepEqual(summary.totals, { completed: 1, blocked: 2, failed: 1, other: 3 });
  assert.equal(summary.buckets.reduce((total, bucket) => total + bucket.total, 0), 7);
  assert.equal(Object.values(summary.totals).reduce((total, count) => total + count, 0), summary.total);
  assert.equal(summarizeActivity([], { now }).total, 0);
  assert.equal(summarizeActivity(records, { now, model: 'model-b' }).total, 0);
  assert.equal(summarizeActivity([...records, record('tool', 'completed', undefined, '')], { now }).total, 8);
  assert.equal(summarizeActivity([...records, record('tool', 'completed', undefined, '')], { now, model: 'model-a' }).total, 7);
  for (const days of [1, 7, 30]) {
    const start = new Date(now - days * 86400000).toISOString();
    const before = new Date(now - days * 86400000 - 1).toISOString();
    const bounded = summarizeActivity([record('start', 'completed', start), record('now', 'completed', new Date(now).toISOString()), record('old', 'completed', before), record('future', 'completed', '2027-01-01T00:00:00Z'), record('invalid', 'completed', 'invalid')], { now, days });
    assert.equal(bounded.total, 2);
    assert.equal(bounded.omitted, 2);
    assert.equal(bounded.buckets.length, days === 1 ? 24 : days);
    assert.equal(bounded.buckets[0].total, 1);
    assert.equal(bounded.buckets.at(-1).total, 1);
  }
  assert.throws(() => summarizeActivity([], { now, days: 0 }), /invalid_activity_range/);
  assert.throws(() => summarizeActivity([], { now: NaN }), /invalid_activity_range/);
  const matched = { ...record('matched-success', 'completed'), output_policy: { result: 'observe', state: 'observed', matched_categories: ['email'] } };
  const unknownCheck = { ...record('unknown-check', 'completed'), output_policy: { result: 'error', state: 'unknown' } };
  const reviewable = [record('clean', 'completed'), matched, record('denied', 'blocked'), record('failed', 'failed'), unknownCheck, record('cancelled', 'cancelled')];
  assert.deepEqual(selectReviewRecords(reviewable).map(item => item.request_id), ['matched-success', 'denied', 'failed', 'unknown-check']);
  assert.equal(selectReviewRecords(Array.from({ length: 12 }, (_, index) => record(`failure-${index}`, 'failed'))).length, 5);
  const original = JSON.stringify(reviewable);
  summarizeActivity(reviewable, { now }); selectReviewRecords(reviewable);
  assert.equal(JSON.stringify(reviewable), original);
  const html = await fs.readFile('internal/server/web/index.html', 'utf8');
  const identifiers = [...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
  assert.equal(new Set(identifiers).size, identifiers.length, 'DOM IDs stay unique');
  const catalogSource = await fs.readFile('internal/server/web/i18n.js', 'utf8');
  const catalog = JSON.parse(catalogSource.split('const chinese = ')[1].split(';\nconst preferenceKey')[0]);
  for (const match of html.matchAll(/data-i18n-parts='([^']+)'/g)) {
    for (const key of Object.values(JSON.parse(match[1].replaceAll('&amp;', '&')))) assert.ok(Object.hasOwn(catalog, key.trim()), `Missing HTML translation: ${key}`);
  }
  for (const match of html.matchAll(/data-i18n-(?:aria-label|placeholder|title)="([^"]+)"/g)) {
    const key = match[1].replaceAll('&amp;', '&');
    assert.ok(Object.hasOwn(catalog, key), `Missing attribute translation: ${key}`);
  }
  console.log('Dashboard checks passed: time boundaries, model filters, outcome totals, unknown states, review queue, unique DOM IDs and bilingual markup.');
}

main().catch(error => { console.error(error); process.exitCode = 1; });
