# Try GovWeave locally

**English** | [简体中文](zh-CN/try-it.md)

Try a real gateway with a scripted local model: allow a normal answer, redact a synthetic email, and block a synthetic credential before it reaches the model. No provider account, API key or model download is needed.

[Watch the 60-second walkthrough](demo/README.md) · [Connect your own application](application-onboarding.md)

## Run the three-case trial

Use Linux, macOS or WSL with **Git, Make, Go 1.24+ and Python 3.10+**, and permission to listen on loopback ports. Use a supported, security-patched Go release; the distribution build pins 1.26.9. This path runs from source, not from the binary-only distribution archive. Node and browser dependencies are not required.

```bash
git clone https://github.com/chongliujia/GovWeave.git
cd GovWeave
make demo-quickstart
```

If you already have this checkout, run only the last command from its root. Cloning or obtaining a Go toolchain may need network access; the trial itself uses only local services and the Python/Go standard libraries. The first build may take longer than later runs.

Expected result after the build:

```text
1/3 Normal answer: HTTP 200, unchanged.
2/3 Synthetic email: HTTP 200, returned Synthetic email: [REDACTED].
3/3 Synthetic credential in input: HTTP 403, blocked before upstream access.
Verified 3 finished audit records and linked evidence; 2 local model requests.
Temporary gateway, credentials and captured content removed.
```

The command finishes automatically. It does not leave a console running. A zero exit status means these three checks passed; a failed check returns 1 and an interrupted run returns 130. The printed summary path is unique to your run.

## What happens during the trial

| Case | What is verified |
| --- | --- |
| Normal answer | Exact synthetic answer returned, HTTP 200, finished audit record |
| Email in model output | `demo.person@example.com` replaced with `[REDACTED]`, HTTP 200, detector and policy revision recorded |
| Credential in input | HTTP 403 with `policy_blocked`, a recorded input-policy match, no upstream request |

The script creates fresh application credentials, scopes input blocking and output redaction to that application, and explicitly enables full evidence capture **only in its temporary instance**. Normal gateway defaults remain unchanged. It checks three evidence records, verifies that ordinary audit logs exclude the synthetic bodies and credentials, and removes the temporary instance, encrypted content and credentials when it exits. Existing `./data`, environment-configured GovWeave instances and Docker volumes are not used.

Only a metadata summary remains under `dist/quickstart/<unique-run>/summary.json` (directory `0700`, file `0600`). It includes request IDs, HTTP status, policy revisions and check results, not application keys or request/response bodies. This directory is ignored by Git.

The local model returns fixed text. These three non-streaming cases demonstrate integration and control behavior; they do not measure real-model safety, detector recall, streaming enforcement, production latency or legal compliance.

## Next: use your own model

Follow [application onboarding](application-onboarding.md) to start a persistent instance, configure a model connection, create an application key, and send one request using the gateway base URL and model alias. Configure the applicable policies explicitly. A selected rule pack does not enable runtime protection.

For a separate support application and tools, continue with the [support Agent trial](support-agent-trial.md). That broader trial intentionally retains a known missed case and can return a nonzero status; it is not the three-case introduction above. For the assessment baseline → fault → recovery workflow, use the separate [local assessment demonstration](local-demonstration.md).

## If the command does not finish successfully

| Symptom | Next step |
| --- | --- |
| `go`, `make` or `python3` is missing | Install the prerequisites and check their versions; on Windows use WSL for these commands. |
| Local services cannot start | Allow loopback listening for the trial. It chooses temporary ports; it does not need port 8080. |
| A check fails | Keep the terminal output and confirm you built the current checkout. A failure is not a successful protection result. |
| You want Chinese output | Run `make demo-quickstart DEMO_LANG=zh-CN`. |
| You have already built the gateway | Run `python3 scripts/demo-quickstart.py`; `--binary /absolute/path/govweave` selects another build. |

The source is [scripts/demo-quickstart.py](../scripts/demo-quickstart.py). Optional walkthrough capture is documented in the [demo asset guide](demo/README.md#refresh-the-walkthrough).
