# Compliance framework integration roadmap

**English** | [简体中文](zh-CN/compliance-roadmap.md)

Status: roadmap with implemented slices identified below; not a claim of complete framework coverage. Source review date: 2026-11-13. GovWeave should connect requirements to scoped evidence, review and remediation, rather than present a list of framework logos or a universal compliance score.

## Baseline and gaps

The [compliance engine](compliance-engine.md) loads versioned JSON packs, evaluates evidence and preserves unknown/manual-review outcomes. The [EU / US starter bundle](eu-us-compliance-bundle.md) adds selected high-risk readiness, GPAI, GDPR, NIST GenAI and FTC claims drafts alongside existing NIST lifecycle and EU transparency packs. These are optional unreviewed packs, not automatic container defaults or full legal coverage. The [ISO preparation checklist and three-framework workflow](framework-workflows.md) are now runnable; licensed ISO clause mapping and organization-wide conformity assessment remain unimplemented.

Products currently bind to one pack/version and require application IDs. The plugin center displays installed definitions and per-control results. Organization-level assessments, multiple framework bindings and authenticated human-review workflows are still planned. A pack's `reviewed` metadata is an operator assertion, not verified approval. Manual controls currently remain `unknown/manual_review_required`.

## Priority catalog

Priorities below are product choices, not claims that every framework applies to every customer. Keep framework type, legal applicability and implementation status separate.

| Priority | Framework | Type | Proposed first useful slice | Current status |
| --- | --- | --- | --- | --- |
| P1 | NIST AI RMF 1.0 and NIST AI 600-1 GenAI Profile | Voluntary framework and companion profile [1][2] | Risk inventory, versioned evaluation evidence, monitoring and response ownership | Partial lifecycle and GenAI evidence drafts available |
| P1 | ISO/IEC 42001:2023 | AI management-system standard [3] | Organization scope, responsibilities, risk treatment, evidence of review and improvement | Public-overview preparation draft available; detailed mapping requires licensed materials and qualified review |
| P1 | EU AI Act | Regulation [4] | Applicability review and evidence requests | Selected transparency, high-risk readiness and GPAI drafts; no whole-Act coverage |
| P2 | China generative-AI service measures and generated-content labeling measures | Regulatory measures [5][6] | Public-service applicability, disclosure/labeling evidence and operational responsibilities | Planned; do not treat every internal AI tool as an in-scope public service |
| P2 | GDPR and China's PIPL | Data-protection legislation [7][8] | Processing inventory, retention, access and impact-assessment evidence | Selected EU GDPR draft available; PIPL planned; detectors do not prove legality |

Use the ISO public overview only for general scope and explicitly non-normative preparation practices. Do not redistribute paid standard text or invent clause-level requirements from a summary. A licensed source and qualified review are prerequisites for publishing a detailed ISO mapping.

EU applicability dates must be versioned by obligation and role, not stored as one timeless “AI Act effective” switch. The Commission's current timeline describes phased application and amended high-risk milestones [4]. Recheck the official text when publishing each pack; this roadmap does not determine customer obligations.

## Delivery sequence

1. **Read-only framework catalog.** Show English-default/Chinese labels, source edition, checked date, jurisdiction, scope, draft/review status, supported slices and explicit exclusions. Separate “available example” from “installed”. Do not enable blocking when a framework is selected.
2. **Scope and evidence model.** Add explicit organization and product assessment scopes plus bounded multi-pack bindings. Migrate existing single-pack products without changing historic reports. Track owner, evidence origin, revision, freshness, missing evidence and applicability rationale. Keep unknown distinct from not applicable.
3. **First evidence-backed packs.** Extend NIST lifecycle evidence and add a clearly labeled ISO readiness draft only after source review. Preserve automatic technical observations separately from supplied declarations and reviewed documents. Link EU transparency evidence to the actual application interface, not merely a boolean.
4. **Human review and remediation.** Add authenticated reviewer identity, decisions with rationale, evidence references, review history, responsible owner and due date. A checkbox or passing synthetic test must not satisfy organizational or legal obligations. This needs a real backend workflow before the UI may claim approval.
5. **Cross-framework reuse and reports.** Map reusable controls to separately versioned requirements; reuse evidence without transferring a pass automatically between frameworks. Retain inputs and source versions for replay. Report pass/fail/unknown/not-applicable counts with denominators and assessment bounds, never “certified”.

## Release acceptance

- Catalog entries and translations are covered by tests; planned items cannot appear as assessed or installed.
- Missing, expired, wrong-scope and caller-declared evidence cannot silently become verified evidence.
- Framework updates create new immutable versions; old reports replay against their retained versions.
- Authorization and audit tests cover document access, review decisions and cross-application evidence isolation.
- Every mapping identifies its source, supporting practice versus obligation, reviewer status and unsupported requirements.
- Technical checks remain advisory to assessment. Enforcement remains an explicit runtime-policy decision.

## Container operating model

Use the existing [Docker Compose deployment](deployment.md#container-deployment): a single Go service, local-only published port by default, non-root user, read-only root filesystem and a persistent data volume. Do not introduce a database or Kubernetes solely to display frameworks. The current file store is single-instance; do not scale replicas over the same volume.

Keep rule-pack releases separate from application builds. Install reviewed, version-pinned packs deliberately in `/data/rule-packs/`, back up the volume, then restart the one service to load them. Validate packs before replacing an installation: invalid packs can prevent startup. Preserve installed versions needed by reports. Do not bundle sample assessments, invented findings, passwords or upstream credentials in images. External access requires an explicit bind decision, HTTPS and access controls.

## Official sources

1. [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework).
2. [NIST AI 600-1 Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence).
3. [ISO/IEC 42001:2023 overview](https://www.iso.org/standard/42001). Public overview only, not full normative text.
4. [European Commission AI Act policy and application timeline](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai).
5. [CAC: Interim Measures for Generative AI Services](https://www.cac.gov.cn/2023-07/13/c_1690898327029107.htm), including Article 2 scope.
6. [CAC: AI Generated and Synthesized Content Labeling Measures](https://www.cac.gov.cn/2025-03/14/c_1743654684782215.htm).
7. [EUR-Lex GDPR text](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng). Candidate source; automated access was blocked during this review, so no clause mapping was verified.
8. [PIPL text published by CAC](https://www.cac.gov.cn/2021-08/20/c_1631050028355286.htm).
