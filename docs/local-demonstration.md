# Local assessment demonstration

**English** | [简体中文](zh-CN/local-demonstration.md)

A real AI application is not required to exercise GovWeave's assessment workflow. The demonstration starts the actual gateway and a separate loopback-only scripted support API, installs the synthetic test suite and NIST lifecycle draft into an isolated temporary instance, and saves the resulting reports. It uses Python's standard library and the built Go binary. No provider account, model download, external service or customer data is required.

## One command

From the source repository:

```bash
make demo
```

This builds the binary and runs four stages:

| Stage | Expected case outcomes |
| --- | --- |
| Normal target, pre-deployment baseline | 4 pass |
| Normal target, operation baseline | 4 pass |
| Intentionally broken target | 2 pass, 2 fail; 2 regressions |
| Repaired target | 4 pass; 2 recoveries |

The four checks look for a synthetic identity sentence, absence of one fake diagnostic canary, an exact denial marker, and JSON syntax. In broken mode, the fixture intentionally emits the fake canary and returns an acceptance marker for an unrelated-account request. Fixed mode restores the normal scripted answers. No real account is read or changed. Mode switches inject drift behind an unchanged target configuration so that comparison can be demonstrated; they are not claims of independently detected deployment versions.

The terminal messages default to English. After building, run a Chinese version with:

```bash
python3 scripts/demo-assessment.py --lang zh-CN
```

## Change behavior manually

```bash
python3 scripts/demo-assessment.py --interactive
```

The launcher first records the pre-deployment and operation baselines. Then enter:

```text
broken
run
fixed
run
unavailable
run
quit
```

`normal`, `broken`, `fixed` and `unavailable` change the scripted target mode. `run` performs an operation-phase assessment, `status` prints the current mode, and `quit` stops the demo. The unavailable mode returns synthetic HTTP errors: cases remain unknown and the last pass is not reused for the current operation test. End-of-input also exits. Use `--lang zh-CN` together with `--interactive` for Chinese terminal messages.

## Reports and lifecycle

Reports are written to a fresh `dist/assessment-demo/<unique-run>/` directory. `summary.json` lists the scenario modes, case counts, regressions and recoveries; `run-01.json`, `run-02.json`, and subsequent files contain actual API results, including synthetic assistant replies. Override the location with `--output-dir NEW_DIRECTORY`; an existing directory is rejected without changing its contents. Files are private `0600` and the result directory is `0700`.

The demonstration deliberately enables response retention for synthetic data. No administrator password, application key or provider credential is exported. It creates a random administrator password in memory and never configures a provider key. The runtime data directory is temporary, separate from `./data` and inherited instance settings. On exit or Ctrl-C, both local services stop and temporary instance state is removed; exported reports remain. A failed run exits nonzero; any completed stage files remain available for diagnosis.

Periodic scheduling is **disabled** in this launcher: the operation phase is exercised by explicit requests. For the actual recurring worker, persisted-plan recovery and scheduling limits, see [Active assessment](active-assessments.md). Its acceptance test covers automatic operation testing after restart. The demo does not connect to an existing instance or change its configuration. It requires local socket permission. Use `--binary /absolute/path/to/govweave` to choose a candidate executable. The launcher is a source-repository development tool, not part of the Go service runtime or binary-only distribution.

## What the result establishes

The local support API is a deterministic fixture, not a trained model. This demonstration verifies that known scripted failures are requested, detected, reported and compared by the actual gateway and evaluator. A matching sentence, one hidden canary or a denial marker cannot establish generally adequate disclosure, privacy or authorization. The suite is not a representative risk benchmark. The NIST draft keeps its human-review items, and reports retain `legal_compliance: not_determined`.

Verify the launcher itself after a build:

```bash
python3 tests/demo-smoke.py
```

It covers batch and interactive use, outage outcomes, report permissions, existing-directory protection, and malformed/oversized fixture requests using local services only.
