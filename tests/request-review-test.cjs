// Classification semantics: an HTTP outcome is not a detector or safety verdict.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
async function main() {
  const source = await fs.readFile('internal/server/web/request-review.js', 'utf8');
  const { reviewRequest, matchesReview, matchesRequestSearch } = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
  const observed = { request_id: 'req_a', application_id: 'app_a', operation: 'chat.completions', outcome: 'completed', http_status: 200,
    output_policy: { result: 'observe', state: 'observed', matched_categories: ['email'], matched_rules: ['email_pattern'] } };
  assert.equal(matchesReview(observed, 'matched'), true, 'completed calls can contain observations');
  assert.equal(matchesReview(observed, 'blocked'), false);
  assert.equal(matchesReview(observed, 'attention'), false);
  const denied = { outcome: 'blocked', error_code: 'model_not_allowed' };
  assert.equal(reviewRequest(denied).matched, false, 'authorization denial must not fabricate a detector match');
  assert.equal(matchesReview(denied, 'blocked'), true);
  assert.equal(reviewRequest({ outcome: 'completed', content_policy: { result: 'disabled', matched_rules: [] } }).checks[0].result, 'disabled');
  assert.equal(reviewRequest({ outcome: 'completed' }).checks.length, 0, 'missing checks remain missing');
  assert.equal(matchesReview({ outcome: 'incomplete' }, 'attention'), true);
  assert.equal(matchesReview({ outcome: 'completed', output_policy: { result: 'error', state: 'unknown' } }, 'attention'), true);
  assert.equal(matchesReview({ output_policy: { result: 'not_applicable', state: 'unknown' } }, 'attention'), false);
  assert.equal(matchesReview({ outcome: 'cancelled' }, 'attention'), false, 'cancellation alone is not a risk finding');
  const tool = { operation: 'tools.invoke', outcome: 'completed', tool_governance: {
    decision: 'allow', content: { state: 'not_observed', rule_ids: [] },
    instruction_policy: { decision: 'allow', state: 'observed', rule_ids: ['task_override'] }, output_policy: observed.output_policy } };
  assert.equal(reviewRequest(tool).matched, true, 'a reviewed instruction may be allowed while its observation remains');
  assert.equal(reviewRequest({ tool_governance: { ...tool.tool_governance, decision: 'block' } }).checks.find(check => check.label === 'Tool credentials').result,
    'not_observed', 'another tool check blocking must not become a credential match or credential block');
  assert.equal(reviewRequest({ tool_governance: { decision: 'block', content: { state: 'unknown', rule_ids: [] } } }).checks[0].result,
    'not_evaluated', 'authorization denial must not imply a credential check was performed');
  assert.equal(reviewRequest({ ...tool, output_policy: observed.output_policy }).checks.length, 3, 'root/tool duplicate output assessment is not double counted');
  assert.equal(matchesRequestSearch({ ...observed, trace: { trace_id: 'abc123', agent_id: 'agent42' } }, ' ABC123 '), true);
  assert.equal(matchesRequestSearch(observed, 'risk app', 'Risk Application'), true);
  assert.equal(matchesRequestSearch(observed, 'email_pattern'), true);
  assert.equal(matchesRequestSearch({ ...observed, body: 'private-marker', credentials: 'secret-marker' }, 'private-marker'), false);
  assert.equal(matchesRequestSearch(observed, '[.*]'), false, 'search is literal, not a regular expression');
  console.log('Request review semantics passed: recorded matches, missing checks, unknown outcomes, tool findings and metadata-only search.');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
