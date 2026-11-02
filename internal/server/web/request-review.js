// Summarize recorded check metadata only. Neither HTTP success nor missing
// observations establish safety; a match can coexist with a completed call.
const list = value => Array.isArray(value) ? value : [];

export function reviewRequest(record) {
  const checks = [], tool = record.tool_governance;
  const input = record.content_policy;
  if (input) checks.push({ label: "Input credentials", result: input.result, rules: list(input.matched_rules),
    categories: [], version: input.ruleset_version, revision: input.revision, unknown: input.result === "error" });
  const output = record.output_policy || tool?.output_policy;
  if (output) checks.push({ label: record.operation === "content.evaluate" ? "Content evaluation" : "Sensitive output",
    result: output.result, rules: list(output.matched_rules), categories: list(output.matched_categories),
    version: output.detector_version, revision: output.revision, unknown: output.state === "unknown" && !["disabled", "not_applicable"].includes(output.result) });
  if (tool) {
    // The overall tool decision may come from another check or authorization.
    // Do not attribute that action to credential detection.
    checks.push({ label: "Tool credentials", result: ["observed", "not_observed"].includes(tool.content?.state) ? tool.content.state : "not_evaluated",
      rules: list(tool.content?.rule_ids), categories: [], version: tool.ruleset_version, revision: tool.tool_revision,
      unknown: false }); // An unauthorized tool need not have executed a content check.
    const instruction = tool.instruction_policy;
    if (instruction) checks.push({ label: "Retrieved instructions", result: instruction.decision,
      rules: list(instruction.rule_ids), categories: [], version: instruction.version,
      revision: tool.tool_revision, unknown: instruction.state === "unknown" });
  }
  const matched = checks.some(check => check.rules.length || check.categories.length);
  const blocked = ["blocked", "rejected"].includes(record.outcome);
  const attention = ["failed", "incomplete"].includes(record.outcome) || checks.some(check => check.unknown);
  return { checks, matched, blocked, attention };
}

export function matchesReview(record, filter) {
  return filter === "all" || Boolean(reviewRequest(record)[filter]);
}

export function matchesRequestSearch(record, query, applicationName = "") {
  const review = reviewRequest(record);
  // Deliberately enumerate metadata. Never search serialized records or bodies.
  const values = [record.request_id, record.application_id, applicationName, record.model, record.operation,
    record.error_code, record.trace?.trace_id, record.trace?.span_id, record.trace?.agent_id,
    ...review.checks.flatMap(check => [...check.rules, ...check.categories])];
  return values.filter(Boolean).join(" ").toLocaleLowerCase().includes(query.trim().toLocaleLowerCase());
}
