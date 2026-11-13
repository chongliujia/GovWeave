# Console screenshots

**English** | [简体中文](../zh-CN/screenshots.md)

These PNGs show the actual embedded GovWeave console in English and Simplified Chinese. They are captured from isolated browser tests with synthetic fixtures, not from an operator's live instance. The overview's activity is mocked; the plugin preview and coverage panels use a disposable local gateway and synthetic upstream. Names, counts and findings are illustrative, not production measurements or compliance results.

The console defaults to English even when the browser locale is Chinese. The language selector switches the interface and persists the preference locally; tests verify both behaviors. User-entered names and rule-pack metadata are not automatically translated.

## Refresh

Follow the [browser-test prerequisites](../development.md#browser-verification), build the current gateway with `make build`, then run:

```sh
node tests/dashboard-smoke.cjs
node tests/plugins-smoke.cjs
```

The plugin test uses `bin/govweave` by default; `GOVWEAVE_TEST_BINARY` can select another current build. Tests start only local synthetic services and require local listening ports and headless Chrome. They need no live provider key and make no paid model calls.

Review the generated images before copying these six files into this directory:

| Source | Published image |
| --- | --- |
| `dist/dashboard-smoke/overview-en-viewport.png` | `overview-en.png` |
| `dist/dashboard-smoke/overview-zh-viewport.png` | `overview-zh.png` |
| Latest successful `dist/plugins-smoke/<run>/redaction-preview-en.png` | `redaction-preview-en.png` |
| Latest successful `dist/plugins-smoke/<run>/redaction-preview-zh.png` | `redaction-preview-zh.png` |
| Latest successful `dist/plugins-smoke/<run>/system-coverage-en.png` | `system-coverage-en.png` |
| Latest successful `dist/plugins-smoke/<run>/system-coverage-zh.png` | `system-coverage-zh.png` |

Only reviewed public screenshots belong here. Keep raw test reports, live instance data, credentials and private captures out of Git. Do not substitute screenshots of a real signed-in instance without reviewing their content and authorization to publish.
