// Minimal Node worker for the synthetic multi-runtime trace demonstration.
// Context is explicit input. No retries, redirects, direct tool URL or logging.
"use strict";
const http = require("node:http");

function id(value, size) {
  return typeof value === "string" && new RegExp(`^[0-9a-f]{${size}}$`).test(value) && value !== "0".repeat(size);
}

async function main() {
  let input = Buffer.alloc(0);
  for await (const chunk of process.stdin) {
    input = Buffer.concat([input, chunk]);
    if (input.length > 8192) throw new Error("invalid_configuration");
  }
  const config = JSON.parse(input.toString("utf8"));
  const endpoint = new URL(config.root);
  const key = process.env.GOVWEAVE_API_KEY || "";
  if (endpoint.protocol !== "http:" || endpoint.hostname !== "127.0.0.1" || endpoint.pathname !== "/" || endpoint.search || endpoint.hash || endpoint.username || endpoint.password ||
      !/^gw_app_[A-Za-z0-9_-]{43}$/.test(key) || !id(config.trace_id, 32) || !id(config.agent_id, 16) ||
      !id(config.parent_span_id, 16) || !/^[a-z0-9-]{1,64}$/.test(config.resource_id) || !/^[a-z0-9-]{1,64}$/.test(config.alias)) throw new Error("invalid_configuration");
  const body = Buffer.from(JSON.stringify({resource_id: config.resource_id}));
  const outcome = await new Promise((resolve, reject) => {
    const request = http.request(new URL(`v1/tools/${config.alias}/invoke`, endpoint), {method: "POST", headers: {
      Authorization: `Bearer ${key}`, "Content-Type": "application/json", Accept: "application/json", "Content-Length": body.length,
      "X-GovWeave-Trace-ID": config.trace_id, "X-GovWeave-Agent-ID": config.agent_id, "X-GovWeave-Parent-Span-ID": config.parent_span_id,
    }}, response => {
      let bytes = Buffer.alloc(0);
      response.on("data", chunk => {
        bytes = Buffer.concat([bytes, chunk]);
        if (bytes.length > 65536) response.destroy(new Error("response_limit"));
      });
      response.on("error", reject);
      response.on("end", () => {
        try {
          const result = JSON.parse(bytes.toString("utf8"));
          const span = response.headers["x-govweave-span-id"];
          const requestID = response.headers["x-request-id"];
          const traceHeaders = response.rawHeaders.filter((_, index) => index % 2 === 0).map(x => x.toLowerCase());
          if (traceHeaders.filter(x => x === "x-govweave-trace-id").length !== 1 || traceHeaders.filter(x => x === "x-govweave-span-id").length !== 1 ||
              response.headers["x-govweave-trace-id"] !== config.trace_id || !id(span, 16) ||
              !/^req_[A-Za-z0-9_-]{22}$/.test(requestID || "") || result.request_id !== requestID ||
              !String(response.headers["content-type"]).startsWith("application/json")) throw new Error("invalid_response");
          // This narrow worker is used only for a deliberately denied resource.
          // A response outside that protocol cannot be counted as a block.
          if (response.statusCode !== 403 || result.error?.code !== "tool_not_allowed" || result.governance?.authorization !== "denied" || result.governance?.decision !== "block" || Object.hasOwn(result, "text")) throw new Error("unexpected_outcome");
          resolve({trace_id: config.trace_id, span_id: span, request_id: requestID, http_status: 403, status: "blocked", reason: "tool_not_allowed"});
        } catch { reject(new Error("invalid_response")); }
      });
    });
    const timer = setTimeout(() => request.destroy(new Error("request_timeout")), 5000);
    request.on("close", () => clearTimeout(timer));
    request.on("error", reject);
    request.end(body);
  });
  process.stdout.write(JSON.stringify(outcome) + "\n");
}

main().catch(() => { process.stderr.write("Trace worker failed.\n"); process.exitCode = 1; });
