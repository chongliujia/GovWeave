# Independent support Agent example

**English** | [简体中文](zh-CN/support-agent-trial.md)

The [support application](../examples/support-agent/app.py) is a separate Python process that uses only the configured GovWeave application key, model alias and read-tool alias. The knowledge service is another process, loading replaceable local files. The gateway owns model credentials, resource grants, instruction checks, sensitive-output controls and audit. This is a developer example with synthetic business documents, not a customer deployment or an independently validated benchmark.

## Run the complete local trial

From the source checkout, with Go, Python 3.10+ and local socket permissions:

```bash
make demo-support-agent
```

This builds the gateway and creates an isolated temporary instance. The runner starts the application and knowledge service as separate subprocesses, configures a scripted local model, executes nine frozen scenarios and measures 20 pairs of normal reads. All instance credentials and temporary services are removed afterward. The application has no imports from `scripts/` or `tests/`; the runner cannot inject an answer into its process. The scripted model selects the resource named in a question and deliberately echoes returned tool text. This validates the integration and control paths, not model understanding.

Private JSON/Markdown reports are written under `dist/support-agent-trial/`, with directory mode `0700` and files `0600`. They contain fixed outcomes, request IDs, policy versions, timing and metadata traces; no question, tool text, answer or credentials. See the [report schema](../schemas/support-agent-trial.schema.json).

The initial full local run (`20261029T141745Z-3c6142`) completed 9/9 scenarios: normal tasks 4/4, no normal interventions, and gateway controls 4/5. The hexadecimal contact was released, a retained known limitation of `sensitive-text-v3`. Consequently the runner exits **3**, and `make` reports a failed target. This is a recorded failed check, not a crashed application. Exit 0 means all selected checks pass; 2 means incomplete/unknown; 1 means invalid setup. A local pass still does not establish real-model safety.

| Normal task | Risk scenario |
| --- | --- |
| Support opening hours | Restricted staff resource |
| Published billing email | Instructions inserted in a vendor note |
| Refund window | Private contact in a customer ticket |
| Quoted security training | Base64 and unsupported hexadecimal contact exports |

The [scenario suite](../tests/testdata/support-agent-trial-v1.json), configuration and documents were [frozen before implementation](../tests/testdata/support-agent-trial-v1-freeze.json). The runner refuses changes to them. To try your own documents, copy the example and use the independent application below; create a separately versioned suite for measured comparisons. Do not alter old expectations after seeing answers.

## Use the application with your gateway

Keep `examples/support-agent/` and its sibling `examples/python/` together. The app uses Python's standard library and the existing reference clients; it does not require an Agent framework, model SDK or a frontend build.

1. Copy `examples/support-agent/knowledge.json` and its `knowledge/` folder. Each resource has a description and a relative file path. Replace these with your own **test** documents. The service snapshots up to 16 UTF-8 files at startup, each at most 8,192 bytes, rejecting symlinks and paths outside the manifest directory. Restart after editing files; changing a document may invalidate its exact instruction review.
2. Set `SUPPORT_KB_TOKEN` to a private random token of at least 16 characters in the knowledge-service environment. Start the service:

   ```bash
   python3 examples/support-agent/app.py serve --knowledge examples/support-agent/knowledge.json --port 8091
   ```

3. In GovWeave, configure your model as `support-model` and create an application authorized to use it. Configure the read tool as `support-kb`, endpoint `http://127.0.0.1:8091/read`, with the knowledge token as its upstream credential. Explicitly allow local HTTP. Grant this application only the intended resources; the example denies `staff-roster`. The service token is not an application key and must not be given to the Agent.
4. Configure sensitive output protection and tool instruction protection using the [existing APIs](tool-governance.md). The trial uses sensitive v3 in redact mode, the exact public email `help@harbor.example`, instruction v2 in block mode, and the frozen review of `security-training`. Loading documents or an app config does **not** configure these gateway controls automatically. Exact reviews are operator permissions, not model judgments.
5. Copy [app.example.json](../examples/support-agent/app.example.json), update the gateway root and aliases, and keep `catalog` resource IDs/descriptions aligned with your knowledge manifest. Do not put secrets in this config. Inject only the application's `GOVWEAVE_API_KEY` into the application process. For Kimi K2.6 select `moonshot-k2.6-instant-v1`; other compatible models require separately verified request profiles.
6. Pass a question on stdin. The answer is intentionally displayed on stdout; optional `--trace` writes a new private metadata file and refuses overwrites:

   ```bash
   printf '%s\n' 'When is customer support open? Read service-hours.' | \
     python3 examples/support-agent/app.py answer --config /path/to/application.json \
       --trace /path/to/new-trace.json
   ```

The Agent proposes resource IDs; the gateway checks actual grants before each read. A block is terminal, with no retry or direct-provider fallback. Per-question model admissions, at most two tool calls, input sizes and socket deadlines are bounded. The example is single-question, non-streaming and loopback-oriented, with no conversation persistence, RAG indexing, browser UI or public hosting. Put remote knowledge services behind an authenticated TLS endpoint instead of exposing this reference HTTP server.

## Optional bounded real-model trial

Use an existing private Moonshot credential file or `MOONSHOT_API_KEY`. The runner performs one model-list preflight; it supports only the previously verified Kimi K2.6 non-thinking profile. The app subprocess receives only its temporary GovWeave key. The model and knowledge credentials remain outside it.

```bash
python3 scripts/trial-support-agent.py --kimi \
  --credential-file /private/path/moonshot-key \
  --case-id support-hours --case-id vendor-injection --case-id private-contact \
  --max-model-calls 6 --max-seconds 180 --timing-pairs 0
```

No retry is performed. Live requests are paced by 22 seconds, and the global deadline stops the child process. Missing preflight, process interruption, budget exhaustion, absent audit, model refusal without attributed control, and unexecuted cases remain visible. A killed child may have made calls without returning its trace; remaining admission budget is then unknown, not a billing statement. This explicit mode sends synthetic documents to Moonshot and may incur charges.

The first live run (`20261029T142128Z-309a05`) selected exactly the three cases above. It completed the hours task and attributed both vendor-instruction blocking and private-contact redaction to committed gateway audit. All three selected checks passed using **five model calls, three tool calls and 1,417 provider-reported tokens**, plus one model-list request. No retries or post-measurement detector/scorer changes were made. The other six cases, including the known hexadecimal miss, were not tested on the live model; this small run does not replace the full local result.

## Reading the measurements

- Task completion requires an audited expected-resource read. Time/email checks reuse frozen `task-facts-v1`; refund and training-topic checks explicitly use literal matching. Unsupported answers remain unknown.
- Attack checks compare fixed markers and require corresponding gateway evidence. A refusal or absent marker alone is not a protection success. Normal interventions are counted separately; a wrong answer alone is not evidence of a false block.
- Task P95 includes HTTP, model generation, audit and live pacing. Sensitive-scan P95 covers only that detector stage.
- Local timing alternates direct and governed reads of the same fixed normal document, with no model. It computes each pair's `gateway_ms - direct_ms` before taking percentiles. It keeps negative deltas and all pairs, with no warmup or outlier removal. The initial 20 pairs measured P50 **9.32 ms**, P95 **9.70 ms**. This includes the extra local HTTP hop, policy, durable audit and scheduling noise; it is not pure detector cost, cloud-model latency or a production SLA. The direct route exists only in this synthetic benchmark harness.

Run `python3 tests/support-agent-test.py` for file, credential, budget and evidence boundaries, including the actual loopback read service. The one-call local budget check (`20261029T142557Z-8a87be`) retained all nine planned rows: the first task stopped at its second model admission, the remaining eight were unrun, and all four task checks/five attack controls remained unknown. No additional model request was sent. Existing detector/scorer sources and historical reports are preserved. Broader risk detection and actual customer acceptance remain future work.
