# System gateway pilot

**English** | [简体中文](zh-CN/system-gateway-pilot.md)

This first increment makes observed routes and unverified system boundaries explicit. It does not transparently intercept every application, RAG or multi-agent message. Applications retain the OpenAI-compatible gateway interface; provider credentials belong to gateway connections, while callers use application keys.

## Instrumented pilot

`examples/support-agent/app.py` is a file-backed knowledge retrieval application, not a vector database or a complete multi-agent system. Its model requests/responses and authorized read-tool requests/responses use the same configured gateway. Denials and invalid trace receipts stop execution without direct-provider fallback, local document fallback or automatic retries.

The default trace joins model → read tool → model using gateway-issued spans. Coordinators can supply `--trace-id`, `--agent-id` and `--parent-span-id`; a parent requires an existing trace ID. These are caller-declared relationships, not authentication or proof of gateway-mediated agent handoffs. Each concurrent task needs its own stateful agent instance. The existing copying `run_traced_agent` helper retains its previous contract; `run_stateful_traced_agent` preserves subclass budgets and closures and restores the transport afterward.

Model-input policy currently detects credential patterns; it is not general input-PII redaction. Output enforcement depends on configured detector, categories, application scope and mode. Read tools also enforce resource grants and their tool policies. The application's user-input/final-output boundary, including content appended by the application, remains separately unverified.

## Console and API

Plugin center → Compliance frameworks / rule packs → select a saved product → **System traffic coverage** → **Refresh coverage snapshot**.

Administrator-only, read-only API: `GET /api/v1/compliance/products/{id}/coverage`.

- Lists currently granted model connections, read tools with at least one resource grant and standalone content checks. Endpoints, credentials, document IDs and payloads are omitted.
- Separates current configuration from observed execution. Configured does not mean used; an observed request may have been blocked before contacting upstream.
- `runtime` counts ordinary operations; `assessment.chat.completions` and `assessment.tools.invoke` populate separate `probes`. Manual trials using ordinary application keys remain ordinary calls, not verified end-user traffic.
- Counts finished, unfinished, blocked, failed, upstream-attempted and traced calls. The most recent runtime call's trace is omitted when that call has no trace.
- Selects product applications from the **global most recent 100 records**. This is neither complete product history, a time-window metric nor a traffic-coverage percentage. Unavailable audit produces null counts, not zero.
- Current policy modes are not historical decisions. Unknown/historical target IDs do not imply a current grant. Unfinished records are not counted as finished; trace receipts do not guarantee durable completion.
- Switching product, editing unsaved product fields, logout and failed reads clear stale displays. Late responses cannot replace another product's view.

Application boundaries, agent handoffs/queues/memory, retrieval outside governed tools and direct-provider bypass paths remain explicitly unverified. Standalone content evaluations do not return redacted text or prove the caller enforced their result. No successful probe or observed request establishes whole-system coverage.

## Use the formal instance

1. Sign in to that instance's admin console. Configure the upstream model and its credential, an application and model grants. Do not use an admin credential for model calls or distribute provider credentials to applications.
2. Deploy the knowledge read service and configure its gateway tool, service credential and resource grants. The gateway container must reach this service over a controlled private network. The example `serve` binds host loopback; container loopback is **not** the host. Do not expose a knowledge service publicly for convenience.
3. Copy `examples/support-agent/app.example.json`, setting the formal gateway root (without `/v1`), granted aliases and resource catalog. Use HTTPS and disable `allow_insecure_http` outside local development.
4. Inject `GOVWEAVE_API_KEY` securely and run a synthetic question from stdin:

```bash
python3 examples/support-agent/app.py answer \
  --config /absolute/path/pilot.json \
  --trace /absolute/path/new-private-trace.json
```

Finish stdin with EOF. This can incur provider charges. It does not start an isolated gateway, change admin configuration or enable schedules. Trace files are newly created with mode 0600 and contain metadata/limitations, not questions, tool output, answers or credentials. Answers use the application's output channel.

5. Bind the application to a saved product. Refresh coverage and correlate the same trace in request audit/task evidence. Verify persisted records, including after restart, rather than relying on client receipts.
6. Configure existing model and read-tool [application assessment plans](application-assessments.md). Scheduling remains explicit opt-in. Keep probes separate from ordinary calls and use existing report archival/replay for retained assessment evidence; the coverage snapshot is not a complete long-term archive.

## Remaining work

Instrument the actual application's input/final-output boundary and internal RAG/agent paths, restrict bypass with deployment network controls, and test each path. This increment adds no arbitrary application reverse proxy, network interception or general input-redaction service. A model `base_url` change alone is insufficient.

This view supports evidence review; it does not automatically pass organizational governance, human-review or incident-response controls in NIST or other frameworks and does not certify compliance.
