# ADR 0001: Start with the self-hosted gateway foundation

**English** | [简体中文](../zh-CN/adr/0001-gateway-first.md)

- Status: Accepted, 2026-10-15. Administrator authentication and the Go language baseline were later superseded by [ADR 0003](0003-password-login.md).
- Scope: The original 0.1.0-dev deployment and initialization slice.

## Context

There is no pre-existing GRC product. GovWeave starts as an open-source, enterprise-deployed gateway for AI access controls and request tracing. The original draft's assumptions of an existing GRC platform, Eval-first launch, and gateway as a second phase no longer apply. Its principles of privacy, truthful evidence, and human-reviewed legal interpretation remain relevant.

Enterprise operators own networking, DNS, certificates, and reverse proxies. GovWeave provides listener configuration, an explicit public URL, an initialization console, and application endpoint examples. Management identity and application identity remain separate.

## Decision

Implement a single-instance Go service with strict configuration APIs, private local persistence, local administrator authentication, and embedded console assets. The initial slice covers deployment, configuration, restart recovery, and endpoint templates. Model proxying, MCP, and regulatory enforcement were not part of that slice; model functionality was added through [ADR 0002](0002-model-gateway.md).

`listen_addr` controls binding. `public_url` is an operator-declared root origin, without `/v1`, other path prefixes, credentials, queries, or fragments. Do not automatically trust Host or proxy headers as configuration. The operator may explicitly use the current browser URL in the console.

Configuration precedence is environment, deployment JSON, saved settings, then defaults. Organization name and public URL expose their source and reject console edits when deployment-managed. Startup and HTTP updates reuse validation. Removing an override falls back to the last complete effective settings saved in the console; document this behavior for operators.

## Tradeoffs at adoption

- Use one process and local private files with atomic replacement. A process lock prevents simultaneous directory use. This is not a multi-tenant SaaS deployment or HA database architecture; a database remains a possible later evolution.
- Embed HTML/CSS/JavaScript in the Go binary, avoiding a frontend build and network dependency. A larger governance workspace may justify a different frontend later.
- The initial version used a high-entropy administrator token in a protected file. This historical choice is superseded by password login and sessions in ADR 0003.
- The initial module baseline was Go 1.22; ADR 0003 raises it to 1.24. The repository distribution toolchain pins Go 1.26.9. Toolchain compatibility is not a production security certification.
- Distribute a local binary archive without model weights, regulatory packages, automatic signing, or public certificate issuance.

## Intended direction

First add model connections and application identity, then versioned request records, MCP execution controls and approvals, and human-reviewed EU/US regulatory mappings. Laws, standards, and voluntary frameworks must remain distinguishable in any future catalog.

Keep future enforcement local and based on reviewed, versioned rules. Regulatory retrieval and heavy analysis do not belong in every synchronous model request. This decision makes no legal compliance or performance claim.
