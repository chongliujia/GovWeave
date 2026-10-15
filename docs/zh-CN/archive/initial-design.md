# 早期产品与研发草案（已归档）

此文档保留早期讨论原文，不代表当前实现或执行计划。当前说明见[文档目录](../README.md)和[架构决策](../adr/0001-gateway-first.md)。

---

# GovWeave — Agent Development Guide

> **文档状态**：架构与研发规范草案 v0.1\
> **项目代号**：GovWeave（暂定名称；对外发布前需核查商标、域名和 GitHub 组织名）\
> **产品定位**：Open Infrastructure for AI Assurance\
> **Slogan**：Evaluate. Observe. Govern.\
> **目标读者**：参与项目的开发者、架构师及 AI Coding Agent

## 0. Agent 工作准则（必读）

你正在参与 **GovWeave**：一个将 **AI GRC、模型与应用评测、运行监控、运行时合规控制** 连接起来的企业级 AI 治理基础设施项目。

开发时严格遵循以下规则：

1. **优先实现可独立使用的开源基础能力**，不要让 Eval CLI、SDK 或 Monitor 的基本运行依赖商业 SaaS、账号注册或私有 GRC 服务。
2. **优先打通端到端闭环**，而不是并行堆砌大量未集成的功能：`AI System → Evaluation/Trace → Finding → Evidence → GRC Adapter`。
3. **数据标准优先**：跨模块共享版本化 Schema、统一标识符和明确的 API 契约；不要让各模块各自定义风险对象。
4. **复用成熟基础设施**：优先集成 OpenTelemetry、现成模型适配器和策略执行引擎，而不是自行重写通用 LLM 网关和可观测性系统。
5. **安全与隐私默认开启**：最小权限、敏感内容不默认采集、凭证不进入日志、按租户隔离和可配置的数据留存。
6. **技术结果不等于法律结论**：任何评测“通过”仅表示在明确范围、版本和测试条件下满足指定技术检查；不得输出“企业已完全满足某法律”等未经验证的结论。
7. **法规转策略必须可追溯并经过授权审批**：LLM 可以给出候选映射，但不能直接将法律解释或模型判断发布成强制生产策略。
8. **区分观察与执行**：SDK/Tracing 只能证明观测到了什么；只有处于受控执行路径、并完成执行确认的 Gateway 才能证明实施了阻断。
9. **生产变更慎重**：高风险 Agent 工具调用的审批、授权和拦截必须发生在真实操作执行前，不能只检查模型生成的文本。
10. **小步提交、可复现验收**：新增功能时同步补充测试、文档、示例和必要的迁移说明；不允许以演示数据冒充生产评测结果。

**优先级原则**：安全与正确性 > 可复现与可审计 > 简单可维护 > 性能优化 > 功能数量。

---

## 1. 产品愿景与边界

### 1.1 愿景

将传统静态 AI 合规管理升级为 **Continuous AI Governance / Continuous AI Assurance**。

完整治理流程：

```text
AI 系统登记
    ↓
法规适用性与风险评估（现有 GRC）
    ↓
上线前模型 / 应用 / Agent 评测（GovWeave Eval）
    ↓
审批与准入（GRC）
    ↓
生产运行监控（GovWeave Monitor）
    ↓
风险事件、复评与整改（GRC）
    ↓
必要时运行时阻断和人工审批（GovWeave Gateway）
    ↓
持续证据、审计与报告
```

### 1.2 目标用户

| 用户 | 首要需求 | 主要入口 |
|---|---|---|
| AI / LLM 开发者 | 自动评测、CLI、CI/CD、Trace | Eval CLI、SDK |
| AI 安全工程师 | Prompt Injection、PII、越权与 Agent 风险 | Eval、Monitor、Gateway |
| AI 平台 / 运维团队 | 接入、可观测性、模型成本、告警 | Monitor、Gateway |
| 法务 / 合规负责人 | 适用法规、风险、控制项、证据、审计 | 既有 GRC 平台与 Enterprise |
| 企业 AI 治理负责人 | 资产、审批、跨部门治理、持续风险 | Enterprise |

### 1.3 MVP 不做什么

- 不训练基础大模型或自建通用大模型推理平台。
- 不开发面向所有模型与 SaaS 的全覆盖发现能力。
- 不承诺自动提供法律意见或一键法律合规认证。
- 不在 v0.1 自研完整分布式 Gateway、高性能 MCP 防火墙或完整企业 SIEM。
- 不在 v0.1 覆盖所有监管框架、多模态输入或所有 Agent 框架。
- 不默认保存完整 Prompt、Response、企业文档或私有测试数据。

---

## 2. 项目命名与开源商业边界

### 2.1 品牌与模块

| 项目 | 职责 | 开放策略 |
|---|---|---|
| **GovWeave** | 项目总品牌、开放标准与生态 | 开源公共组件 |
| **GovWeave Eval** | 模型、RAG 应用和 Agent 评测 | 开源优先 |
| **GovWeave Monitor** | Tracing、Metrics、风险事件采集与展示 | 开源优先 |
| **GovWeave Gateway** | 受控 API / Tool 调用、策略执行 | 第二阶段，基础能力逐步开源 |
| **GovWeave Enterprise** | 完整 GRC、法规知识服务、审批、跨系统治理与高级证据管理 | 独立商业产品 |

### 2.2 Open Core 原则

**开源**：SDK、CLI、评测运行器、基础检测器、扩展接口、事件与证据 Schema、基础报告导出、OTel 集成和可独立部署的轻量监控服务。

**商业化**：法规适用性服务、专家维护的控制映射、企业策略集中编排、跨部门审批与整改、多组织治理、企业审计工作流、高级连续合规证据关联、企业级支持。

- 开源工具应可离线或自托管运行；可选联网模型评测由用户自行提供 API 凭证。
- 不通过锁定基础评测结果、Trace 或证据导出来强迫客户付费。
- 建议公共仓库使用 **Apache-2.0**；Enterprise 独立私有仓库与商业许可。实际采用前检查第三方依赖、测试集、模型与标准文本许可。
- **不要**将客户专有规则、真实个人信息、商业秘密、未经授权的数据集或受版权保护的标准全文提交到开源仓库。

---

## 3. 总体技术架构

### 3.1 三个平面 + 共享治理契约

- **Evaluation Plane**：批量 / 离线评测、回归测试、红队与报告，不在生产请求同步路径中。
- **Observation & Enforcement Data Plane**：采集运行信号；在明确受控路径上执行低延迟策略、拦截和工具审批。
- **Governance Control Plane**：GRC 资产、风险和控制目录、适用政策、审批、整改、审计证据与报表。
- **Shared Contract Layer**：版本化 AI System、Evaluation、Finding、Control、Evidence、Trace 及策略记录 Schema。

```mermaid
flowchart TB
    Users[AI 开发者 / 安全 / 合规 / 审计]
    GRC[Existing GRC / GovWeave Enterprise\n资产 · 法规 · 风险 · 控制 · 报告]
    Core[Shared Governance Contracts\nAI System · Control · Finding · Evidence]
    Eval[GovWeave Eval\nCLI · Runner · Detectors · Reports]
    Monitor[GovWeave Monitor\nSDK · OTel Collector · Trace · Alerts]
    Gateway[GovWeave Gateway (Phase 2)\nAPI Proxy · Policy · Tool Guard]
    App[企业 AI 应用 / RAG / AI Agent]
    Models[外部 / 私有模型与工具]
    Storage[(PostgreSQL + Object Storage)]

    Users --> GRC
    GRC <--> Core
    Eval <--> Core
    Monitor <--> Core
    Gateway <--> Core
    App --> Monitor
    App --> Gateway
    Gateway --> Models
    Eval --> Models
    Eval --> Storage
    Monitor --> Storage
    Gateway --> Storage
    Core --> Storage
```

> 图示为逻辑依赖。生产架构必须将 **同步强制决策** 与 **异步遥测、报告和分析** 分开；不能因上报审计事件失败而不加区分地影响所有在线业务。

### 3.2 系统级设计原则

1. **模块化单体优先**：初期避免过早拆微服务；CLI、API、Worker、Web 可分进程运行但共享契约。
2. **无状态服务优先**：API 与 Runner 可以水平扩容，持久状态存 PostgreSQL / 对象存储。
3. **事件驱动关联**：评测、Trace 和 Gateway 事件采用共同信封（Event Envelope），异步输入风险与证据工作流。
4. **Policy Decision / Policy Enforcement 分离**：策略判断与真实拦截明确区分，并记录各自结果。
5. **可审计版本**：模型、Prompt、工具、测试集、检测器、策略、控制目录与证据 Schema 均需要版本标识。
6. **不强绑定第三方产品**：外部模型、Promptfoo、Langfuse、LiteLLM 等均通过 Adapter 接入；核心数据模型不依赖供应商私有字段。

---

## 4. 推荐技术栈

| 层 | 默认选择 | 使用时机 / 备注 |
|---|---|---|
| Python Runtime | Python 3.12+ | 评测、SDK、后端；在 CI 中固定并测试支持版本 |
| Python 包管理 | `uv` workspace | Monorepo 依赖与构建 |
| API 服务 | FastAPI + Pydantic v2 | 类型化 API、OpenAPI、请求校验 |
| CLI | Typer | `govweave eval ...` |
| 评测执行 | Python async + pytest | Runner、测试与可重放实验 |
| 模型接入 | Adapter Interface；可选 LiteLLM | 不把上游模型接口写死在核心库 |
| Web | Next.js + React + TypeScript | Monitor Web；商业 GRC 独立交付 |
| UI | Tailwind CSS + shadcn/ui | 控制台组件 |
| JS 包管理 | pnpm workspace | Web 与 TypeScript SDK |
| 可观测性 | OpenTelemetry SDK + OTLP Collector | 优先遵守 GenAI 语义约定，适配器管理其版本变化 |
| 主数据库 | PostgreSQL | 资产、评测元数据、风险、证据索引 |
| 证据对象存储 | S3 兼容 / MinIO | 评测产物、加密证据文件 |
| 后台任务 | 初期简单异步 Worker；规模化后 Celery + Redis | 避免 MVP 引入不必要的运维组件 |
| 大规模 Trace 分析 | ClickHouse（后续） | 量级需要时才加入 |
| 策略执行 | OPA / Rego（Gateway 阶段） | 可嵌入或独立部署，策略需要版本、审批与回滚 |
| 本地部署 | Docker Compose | 本地演示与集成测试 |
| 企业部署 | Kubernetes（后续） | 仅在高可用与客户环境需要时引入 |
| CI | GitHub Actions | lint、typecheck、unit/integration/security tests |

**不要无依据地升级依赖或盲目选择“最新”版本**；新增依赖须说明用途、开源许可证、维护状态和供应链风险，并更新锁文件。

---

## 5. 代码仓库与模块职责

建议使用 **Monorepo**，共享 Schema，发布时可以拆成独立包。

```text
govweave/
├── AGENTS.md                     # 可选：将本文件复制成受 Agent 工具自动识别的名称
├── apps/
│   ├── eval-cli/                # CLI 入口、配置、格式化输出
│   ├── monitor-api/             # 监控查询、事件与证据索引 API
│   ├── monitor-web/             # 基础 Trace 与风险事件 UI
│   └── gateway/                 # Phase 2：API / Tool Policy Gateway
├── packages/
│   ├── core/                    # 公共 Python 数据类型、ID、Schema 兼容
│   ├── eval/                    # Runner、Providers、Datasets、Scorers
│   ├── detectors/               # PII / Injection / Policy 检测接口与实现
│   ├── sdk-python/              # Python Instrumentation & Event SDK
│   └── sdk-typescript/          # TypeScript SDK（后续）
├── schemas/
│   ├── ai-system/
│   ├── evaluation/
│   ├── finding/
│   ├── control/
│   ├── evidence/
│   ├── trace/
│   └── event/
├── integrations/
│   ├── opentelemetry/
│   ├── promptfoo/
│   ├── litellm/
│   └── grc-adapter/              # 可配置的企业 GRC 连接层
├── examples/
│   ├── basic-llm/
│   ├── rag-agent/
│   └── grc-sync/
├── infra/
│   ├── docker/
│   └── otel-collector/
├── docs/
│   ├── architecture/
│   ├── guides/
│   └── adr/                      # 架构决策记录
├── tests/
├── pyproject.toml
├── pnpm-workspace.yaml
├── docker-compose.yml
├── LICENSE
└── README.md
```

> 说明：上面的路径是**规划结构**，不是对现有仓库文件状态的声明。尚未实现的目录不要用空目录伪装已交付能力。

---

## 6. 核心领域模型与数据契约

### 6.1 必须统一的实体

| 实体 | 主键 | 必须记录的概念 |
|---|---|---|
| Tenant | `tenant_id` | 组织及隔离边界 |
| AI System | `ai_system_id` | AI 应用名称、用途、负责人、环境 |
| System Version | `system_version_id` | 模型、Prompt、工具、配置的不可歧义版本引用 |
| Evaluation Run | `eval_run_id` | 测试配置、数据集、执行环境、起止时间、结果 |
| Test Case | `test_case_id` | 用例目标、输入引用、期望与评分方法 |
| Runtime Trace | `trace_id` | 任务/请求链、Span、模型与工具操作 |
| Risk Finding | `finding_id` | 来源、严重程度、状态、相关证据 |
| Control | `control_id` | 控制目标、适用性、执行方式、法规映射 |
| Policy | `policy_id` + `policy_version` | 审批后的机器可执行策略 |
| Evidence | `evidence_id` | 内容哈希、来源、访问控制、保留期限 |
| GRC Assessment | `assessment_id` | 合规/风险评估及人工审查状态 |

### 6.2 关键关联

```text
Tenant
  └── AI System
        └── System Version
              ├── Evaluation Run ── Test Case ── Risk Finding
              ├── Runtime Trace ── Risk Finding
              ├── Policy / Control
              └── Evidence ── Control ── GRC Assessment
```

每条 Finding 必须知道它来自 **评测**、**在线监控**、还是 **网关执行**。不要把“检测器命中”“策略决定”“实际阻断成功”合并成单一状态。

### 6.3 统一事件信封（建议 Schema v0.1）

```json
{
  "schema_version": "0.1.0",
  "event_id": "evt_demo_001",
  "event_type": "evaluation.finding",
  "timestamp": "2026-10-15T00:00:00Z",
  "tenant_id": "tenant_demo",
  "ai_system_id": "customer-agent",
  "system_version_id": "v1.2",
  "source": "govweave-eval",
  "trace_id": null,
  "eval_run_id": "run_001",
  "test_case_id": "pii-exfiltration-01",
  "control_id": "AI-DATA-001",
  "finding_id": "finding_001",
  "severity": "high",
  "result": "fail",
  "evidence_id": "evidence_001",
  "detector_version": "0.1.0",
  "metadata": {}
}
```

约束：

- 上例为**示例数据**，不是外部行业标准，也不是已运行测试结果。
- ID 在各模块之间必须稳定，跨租户查询必须拒绝。
- 时间戳统一使用带时区的 ISO 8601（API 默认 UTC）。
- Schema 显式版本化；重大变更提供迁移、兼容策略和契约测试。
- `metadata` 不允许任意放入 Prompt 明文、私钥、认证令牌或敏感个人信息。
- Trace/Telemetry 事件映射遵循 OTel 标准；GovWeave 特有属性采用命名空间并维护兼容表。
- `evidence_id` 应能定位带来源、哈希和访问权限的证据对象；哈希证明字节完整性，不证明采集覆盖率和法律合规性。

### 6.4 GRC 映射方式

```text
Regulatory Requirement
   → Control Objective（人工审核）
   → Technical Check / Policy（版本化）
   → Eval Result / Runtime Event / Enforcement Result
   → Evidence
   → Risk Assessment / Remediation / Report
```

要求：保留法律适用条件、业务情境、法规文本版本、适用角色（如 Provider/Deployer）、人工复核结论及技术测试的适用范围。不要硬编码法律阈值。

---

## 7. 模块 1：GovWeave Eval（首发）

### 7.1 v0.1 范围

- 可安装 Python 包与 CLI；本地运行不要求登录商业服务。
- Provider Adapter：至少支持一个 OpenAI-compatible 测试目标，接口便于扩展其他模型/应用。
- Dataset：JSONL/YAML 数据集加载、版本与内容校验；基础自定义用例。
- Runner：异步执行、并发限制、超时、重试、结果追踪与成本/Token 统计（可得时）。
- Detectors/Scorers：基础 PII、Prompt Injection、规则匹配、自定义评分器插件；明确输出置信度及局限。
- Reports：机器可读 JSON 与人类可读 Markdown；报告包含测试环境、模型、配置、测试集版本、失败样本引用与证据。
- CI：支持显式阈值与退出码，失败语义与工具执行失败区分。
- GRC：通过开放 Adapter 将 Finding/Evidence 同步至现有 GRC；未配置时仍可完整导出本地结果。

建议使用体验（目标命令，须在实现后验证）：

```bash
govweave eval run --config govweave.yaml
govweave eval report --run <run-id> --format json
govweave eval report --run <run-id> --format markdown
```

### 7.2 评测准确性要求

- 区分安全风险**测试用例成功触发**、**检测器发现风险**、**被测系统实际发生违规操作**。
- 报告假阳性、假阴性、样本数量、测试配置和评分器版本；不能只给单个总分。
- 对 LLM-as-a-Judge 记录 Judge 模型、提示模板、重复测试设置和不确定性；不要让模型判断无条件成为最终合规认定。
- 针对危险工具或真实外部系统的红队测试必须在明确授权的隔离环境进行；默认模拟真实副作用。
- 保存失败用例的复现所需参数引用，敏感输入由客户控制是否加密存储。

### 7.3 扩展接口（先定义协议再实现）

```text
Provider.generate(request) -> model_response
Dataset.load(path) -> test_cases
Scorer.score(case, model_response, context) -> score_result
Detector.detect(data, context) -> risk_signals
EvidenceWriter.write(artifact, metadata) -> evidence_ref
GRCAdapter.push_finding(finding, evidence_ref) -> sync_result
```

接口需支持取消、超时、错误分类和可插拔实现。

---

## 8. 模块 2：GovWeave Monitor

### 8.1 v0.1 范围

- Python SDK 与 OpenTelemetry GenAI 集成；TypeScript SDK 作为后续扩展。
- 接收/关联 Trace、Span、基础 Metrics、模型调用、RAG 检索和 Agent 工具事件。
- 提供最小可用的 Trace Viewer、应用维度统计与风险 Finding 列表。
- 基于 `tenant_id / ai_system_id / system_version_id` 查询，权限检查贯穿 API 与存储。
- 支持采样、脱敏、数据保留期限和必要元数据；默认不采集完整输入/输出。
- 监控发现的问题能够生成 Finding，关联 Control 和 Evidence。

### 8.2 核心运行指标

- 可观测性：请求量、错误率、延迟、Token/成本（可得时）。
- 质量：反馈、任务完成情况、已配置的质量评分。
- 安全/治理：风险信号、策略命中、工具行为、已接入应用覆盖情况。
- 审计：事件来源、收集失败数、事件延迟、丢失量估计和留存状态。

**不得**把“已接入应用监控覆盖率”宣称为“全企业 AI 使用覆盖率”。未经授权或未接入的 SaaS / Shadow AI 不在 v0.1 监控承诺内。

---

## 9. 模块 3：GovWeave Gateway（第二阶段）

### 9.1 功能目标

- 模型访问控制：应用身份、模型白名单、额度/速率、数据区域及接收方规则。
- 请求/响应检查：必要的 PII、秘密信息、风险检测与策略执行。
- Agent/MCP 控制：在真实工具边界校验工具名称、参数、调用主体和操作权限。
- 执行动作：`ALLOW`、`REDACT`、`REQUIRE_APPROVAL`、`BLOCK`。
- 输出结构化 **Policy Decision**、**Enforcement Result** 与 **Evidence**，不能混淆。

### 9.2 关键安全规则

- 任何高风险、不可逆操作应在执行前完成授权；审批必须绑定准确的操作参数、身份、版本、过期时间，并防止重放。
- 不接受“检查了 LLM 生成的 tool_call 文本”作为工具真实受控的证明。
- 对 Streaming 输出设计缓冲/分段扫描；在内容已经发出后才检测不能算成功阻断。
- 根据操作风险配置 Fail-open/Fail-closed；高风险操作不得在执行控制失效时静默放行。
- 同步路径优先采用确定性规则与低延迟检测；重型分析异步处理。
- 第一期可以集成 LiteLLM 和 OPA，**不要从零重写**通用 API Proxy 和策略引擎。

---

## 10. 模块 4：GRC / Enterprise 集成

用户已拥有 GRC 产品能力：**法规解读、风险评估、合规报告**。原则上应**复用现有能力，不在开源仓库重造完整 GRC**。

公开仓库只提供：

- 通用 `GRCAdapter` 接口与安全认证方式；
- Finding / Evidence / Control 同步契约；
- 去重、重试、幂等、冲突处理和错误回执；
- 不包含客户隐私数据的 Mock GRC 示例服务；
- 可选的控制项外部 ID 映射。

企业版扩展：

- 法规知识服务与专家审核的控制映射；
- AI 资产台账、审批与整改任务；
- 持续合规状态、证据索引与审计工作流；
- 组织权限、企业级身份、隔离与私有化部署；
- 与评测、监控、网关联动的持续风险复评。

**同步原则**：GRC 不可用不得导致本地评测结果丢失；应使用可重试的幂等事件提交与失败记录。

---

## 11. API 与事件规范（初始建议）

实际实现前先产出 OpenAPI 与 JSON Schema，并由契约测试约束。推荐起始 API：

```text
POST   /v1/ai-systems                 # 登记 AI 系统（权限受控）
GET    /v1/ai-systems/{id}            # 查询系统档案
POST   /v1/evaluations                # 创建评测任务
GET    /v1/evaluations/{id}           # 查询状态与结果
GET    /v1/evaluations/{id}/report    # 导出报告
POST   /v1/findings                   # 上报检测结果（服务鉴权）
GET    /v1/findings                   # 按资产/版本/控制查询
POST   /v1/evidence                   # 申请上传证据/保存元数据
GET    /v1/evidence/{id}              # 权限受控的元数据查询
GET    /v1/traces/{id}                # 查询已授权 Trace
```

- 这些是**待确认的目标接口**，并非现成已部署服务。
- 所有列表接口必须做租户作用域过滤、分页、时间窗口和访问权限校验。
- 写操作支持幂等键；错误应使用结构化代码与 Trace ID。
- 证据文件最好通过短期授权对象存储 URL 传输，避免任意文件上传造成 API 服务压力。

事件类型候选：

```text
evaluation.started
evaluation.completed
evaluation.finding
runtime.trace_observed
runtime.risk_detected
policy.decision
policy.enforcement_result
evidence.created
grc.sync_requested
grc.sync_completed
```

---

## 12. 安全、隐私与可信合规要求

以下要求从 MVP 起即为基本门槛：

### 12.1 数据安全

- 按租户隔离；用户、服务、API Key 均应绑定明确的租户/角色/作用域。
- 凭证通过环境变量或 Secret Manager 注入；日志、异常、Telemetry 不输出秘钥。
- 默认仅记录必要元数据；Prompt、Response、工具参数和文件内容需显式授权采集。
- 提供脱敏与访问权限检查；证据应加密存储并支持留存/删除策略。
- 默认不向第三方遥测或外部平台发送企业原始数据。
- 外部模型评测明确告知将数据发送给哪个提供商；测试数据使用者必须具备授权。

### 12.2 防护与信任边界

- 外部模型响应、检索内容、网页和测试数据均属于不可信输入，不得直接被解释为系统指令。
- 不可信评测插件、脚本和 Agent 工具尽量在隔离沙箱或受限进程运行。
- 接口需要限流、输入大小限制、超时和拒绝服务防护。
- Agent 外部副作用应以 Mock 或受限测试环境为默认；生产动作必须受控。

### 12.3 审计证据

- 记录证据来源、采集时间、系统/策略/测试版本、关联实体与完整性哈希。
- 能够区分**已部署策略**、**已完成检查**、**执行成功**与**日志缺失/覆盖未知**。
- 哈希和签名可证明特定记录未被改动，**无法自动证明记录包含全部行为**。
- 合规报告中标注测试范围、盲区、假设、适用法规版本和人工审查项。

### 12.4 合规表述红线

- 禁止自动将模型输出映射为“完全 GDPR / EU AI Act / ISO 42001 合规”。
- 禁止把标准控制项模板当作已获得第三方认证。
- 禁止未经专业审核将法规文本生成的候选策略直接上线。
- 需要法律适用性判定时保留负责人审批和明确证据链。

---

## 13. 测试、工程质量与交付标准

### 13.1 开发规范

- Python：类型标注、Pydantic 输入输出模型、明确错误类型；代码格式与静态检查在 CI 运行。
- TypeScript：严格类型检查；API 客户端尽量从 OpenAPI / Schema 生成。
- 复杂架构选择记录 ADR（Architecture Decision Record）。
- 新功能至少包含：功能实现、测试、文档、示例配置和安全影响说明。
- 不提交真实 API Key、客户数据、可执行恶意载荷或不可分发的测试材料。

### 13.2 必须具备的测试类型

1. 单元测试：事件校验、控制映射、评分器和权限过滤。
2. 契约测试：Schema 版本兼容、API 返回结构、Adapter 错误处理。
3. 集成测试：Eval → Evidence → GRC Mock；SDK → Collector → Monitor 查询。
4. 安全测试：租户串读、凭证泄露、输入边界、权限绕过、敏感数据落盘。
5. 回归评测：固定测试集和可复现配置；记录检测误报与漏报。
6. 压力测试：任务并发、事件摄入与查询；Gateway 推进后增加 p95/p99 延迟及失败模式测试。

### 13.3 完成定义（Definition of Done）

一个功能只有在以下条件同时满足时，才能标记为 Done：

- 满足对应需求和可验证的验收用例；
- 测试通过，错误与边界情况有处理；
- Schema/API 有版本策略且文档更新；
- 已检查租户安全、敏感数据处理及依赖许可；
- 示例可由全新环境按文档复现；
- 没有把尚未支持的能力写成已实现能力。

---

## 14. 12 周 MVP 实施计划

> 假设 3–5 名熟悉 Python、前端与部署的工程师，且现有 GRC 有可调用接口。该周期是规划目标，不是交付保证。生产级 Gateway 不包含在 12 周范围内。

| 周期 | 开发重点 | 阶段交付 |
|---|---|---|
| Week 1–2 | Monorepo、CI、ID 规则、AI System / Finding / Evidence Schema | 可安装 `core`、示例、契约测试 |
| Week 3–5 | Eval Runner、模型适配、数据集、基础检测、JSON/Markdown 报告 | 可独立运行的 Eval CLI |
| Week 6–8 | Python SDK、OpenTelemetry、采集 API、Trace Viewer | 自托管 Monitor 可观察 RAG Agent |
| Week 9–10 | GRC Adapter、控制项关联、风险发现、证据同步 | Eval/Monitor → GRC 闭环 |
| Week 11–12 | 安全检查、容器化、文档、试点、性能与集成测试 | GovWeave v0.1 发布候选 |

### v0.1 四项不可妥协的验收场景

- [ ] 开发者**无需注册商业平台**，可以本地运行一次完整 AI 应用安全评测。
- [ ] 开发者能通过 Python SDK 将模拟或授权的 RAG Agent Trace 发到自托管 Monitor，并在 UI 中查看。
- [ ] 评测失败记录或监控风险事件可以关联同一 AI System / System Version / Control，并通过 Mock GRC Adapter 同步。
- [ ] 合规人员能导出可追溯的技术评测和证据报告，包含测试环境、版本、来源、范围与限制。

---

## 15. 研发任务执行顺序（给 Coding Agent）

收到具体开发任务时遵循以下流程：

1. **读取当前仓库**：确认实际目录、现有依赖、测试和已实现能力；不要仅凭本文件推断代码已经存在。
2. **确认模块边界**：标注工作属于 `core` / `eval` / `monitor` / `gateway` / `grc-adapter` 中哪部分。
3. **先给简短实现计划**：明确输入输出契约、持久化变化、风险和验收方式。
4. **先更新共享 Schema，再实现生产者与消费者**；改变事件字段时添加兼容与迁移测试。
5. **优先交付最小端到端切片**：可以在本地跑通，然后再扩展配置与 UI。
6. **执行质量检查**：运行仓库已有 lint、typecheck、unit/integration tests；若无法运行，要明确阻碍与未验证部分。
7. **更新 README、示例和 ADR**：附上运行命令、依赖前提和限制。
8. **报告结果**：说明完成项、改动文件、测试结果、已知限制及下一步，不虚构构建成功或 benchmark 数值。

### 默认优先顺序

```text
P0  Shared Schemas + IDs + Event Envelope
P1  GovWeave Eval CLI + Reports
P2  Monitor SDK + Trace & Finding API
P3  GRC Adapter + Evidence Loop
P4  Gateway Policy & Enforcement (after v0.1)
P5  Enterprise-scale Security / Multi-region / Advanced Agent Governance
```

---

## 16. 最终产品原则

**GovWeave 的核心不是“又一个 LLM API 网关”，而是让每个 AI 系统都有可追溯的治理链条：**

```text
What was assessed?
  → What was tested?
  → What happened in production?
  → Which control applied?
  → Was it enforced?
  → What evidence supports the conclusion?
  → Who approved and remediated the risk?
```

**短期目标**：开源 Eval + Monitor + 通用 Schema，打通现有 GRC。\
**中期目标**：持续评测、监控事件、控制措施与审计证据的自动关联。\
**长期目标**：Agent Runtime Compliance Gateway + Continuous AI Assurance。

> 对所有 AI Coding Agent 的最终要求：**先实现可信、可验证、可独立运行的最小闭环；不要以功能数量替代工程质量、控制有效性与证据可信度。**
