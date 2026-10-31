# 主动测评与生命周期测试

[English](../active-assessments.md) | **简体中文**

GovWeave 现在可以通过现有网关，对已配置的 Chat Completions 连接或读取工具执行有界测试。管理员登记测试计划，发起部署前或运行期间测评，查看私有证据与现有规则引擎生成的评估。无需新增后台页面或运行依赖。

## 安装与执行

没有真实目标时，可使用[本机脚本演示](local-demonstration.md)，通过真实网关和引擎验证已知缺口的执行与发现。

将两类声明式插件安装到实例的数据目录，再重启：

```bash
mkdir -p data/test-suites data/rule-packs
cp examples/test-suites/chat-contract-smoke.json data/test-suites/
cp examples/rule-packs/nist-ai-rmf-lifecycle.json data/rule-packs/
```

使用现有产品接口登记产品，绑定应用，并选择精确的 `nist-ai-rmf-lifecycle` / `0.1.0` 规则包。将[测试计划示例](../../examples/test-plan.json)中的 `application_id`、`model_alias` 替换为该产品已绑定的应用和获授权且启用的模型别名。明确填写目标版本与使用场景。`target_version` 是管理员登记的标识，软件不会独立识别远端模型权重或应用代码版本。

以下接口均要求管理员会话；写入同时要求 `Content-Type: application/json`、`X-GovWeave-Request: console` 和现有来源校验。应用推理密钥无法调用管理接口。

| 接口 | 用途 |
| --- | --- |
| `GET /api/v1/compliance/test-suites` | 查询测试包版本和内容摘要 |
| `GET /api/v1/compliance/test-suites/{id}/versions/{version}` | 读取精确测试包 |
| `GET, PUT /api/v1/compliance/products/{id}/test-plan` | 读写原有默认计划，首次提交 revision 为 0 |
| `GET /api/v1/compliance/products/{id}/test-plans` | 列出至多两个计划，包含已有默认计划 |
| `GET, PUT /api/v1/compliance/products/{id}/test-plans/{plan}` | 读写命名 `model`／`read_tool` 计划，每个目标类型只能有一个 |
| `POST /api/v1/compliance/products/{id}/test-runs` | 请求体指定 `phase`，命名计划另指定 `plan_id`，省略时选择默认计划；异步返回 `202` |
| `GET /api/v1/compliance/products/{id}/test-runs` | 按时间倒序查询历史记录 |
| `GET /api/v1/compliance/test-runs/{run}` | 查询运行状态、逐项结果、版本、证据和规则评估 |
| `POST /api/v1/compliance/test-runs/{run}/replay` | 请求体 `{}`，只重放历史规则判断，不调用目标 |

轮询运行 ID，直到 `state` 不再是 `running`。`status: passed` 仅表示选定的全部检查通过；`failed` 表示至少一项失败，其他项仍可能未知；`inconclusive` 表示证据无法确定全部结果。请求失败、endpoint_output 检查被网关拦截、工具调用、空输出、不支持的响应或 `finish_reason` 不是 `stop` 时保持未知。取消或执行中产品／计划／网关／策略版本变化会返回错误，不生成评估。重新运行会向目标发出新请求，历史重放不会。

## 测试包与规则包

另新增 `output_protected` 和 `output_allowed`，均使用 `scope: gateway_control` 和已写审计的网关执行回执。内置 `sensitive-output-controls` 包含三类挑战及正常对照，其当前部署前／运行期证据可配合规则包 1.1.0 进入产品报告，见[主动输出控制测评](output-control-assessments.md)。这两种检查即使开启 `retain_responses` 也不保存返回正文；类别挑战不存正文摘要，正常对照保留摘要用于精确比对。

读取工具套件设置 `target_kind: read_tool`，用 `resource_id` 替代消息，只允许 `output_protected`、`output_allowed`、`tool_denied`。计划使用 `tool_alias`，不填写模型字段；拒绝检查要求在上游 I/O 前拒绝资源且提交审计。五项套件、独立产品事实与权限变化处理见[主动读取工具测评](tool-control-assessments.md)。

每产品允许每种目标各一个计划，包含已有默认计划。命名计划通过 `{"plan_id":"model","phase":"operation"}` 或 `read_tool` 选择。[同一产品的模型与工具测评](application-assessments.md)介绍组合报告、重复目标拒绝及兼容方式。产品报告可以包含模型／工具共四项阶段事实，单次测试评估仍只针对自己的计划。

`canary_absent` 使用版本化检测器及每项新生成的合成标记，模板约定、实测召回、已知漏检、证据及执行器兼容性见[标记检测与验证](canary-validation.md)。

测试包定义消息、测量范围与检查方式。支持精确 `equals`、区分大小写的 `contains` / `not_contains`、`json_valid`、`manual`、`canary_absent` 和 `credential_block`。最后一项检查网关是否返回 `403 policy_blocked`，必须标为 `scope: gateway_control`；此列表中的其他项为 `scope: endpoint_output`。网关拦截不能证明上游模型会如何回答。人工检查始终未知；JSON 语法正确不代表满足 Schema 或语义；关键词检查不代表普遍安全、隐私或公平性。

`chat-contract-smoke` 示例有两个合成用例，分别检查字面标记和 JSON 语法，是执行示例，不是代表性风险基准。每项每轮只请求一次，temperature 为 0，输出预算由计划指定。提供者可能忽略采样控制，重复执行仍可能变化。目前没有 LLM 裁判或自动生成测试题。

规则包继续定义适用性、要求、出处与证据条件，不执行网络或脚本。主动测评将产品和网关快照与服务器生成的 `testing.test_set_documented`、`testing.pre_deployment.passed`、`testing.operation.passed` 合并，交给同一确定性引擎。产品资料禁止定义 `testing.*`。无状态评估 API 仍信任调用者提交的来源标签。

只有产品修订、计划 ID／修订、测试包摘要、网关和策略版本、留存的工具配置版本、连接 ID／修订及规则包内容一致时，才能关联不同阶段的证据。工具目标另固定工具 ID／修订及执行器代次。执行期间修改工具配置会产生 `test_source_changed`，不会发布该次评估。加入工具证据之前的旧记录仍可重放、与同类旧记录比较，但不能作为含工具证据的新记录的基线。同阶段最近的失败或不完整记录会阻止继续使用更早的通过结果。部署前证据默认 30 天过期，运行期证据默认两倍复测间隔后过期；这些是产品默认值，不是 NIST 指定期限。历史报告描述当时结果，不是当前上线许可。合并测试证据后的评估保存在**主动测评记录**中；产品 `/evaluation` 接口也会合入有效输出控制测试的两项阶段事实：模型为 `testing.output.*.passed`，工具为 `testing.tools.output.*.passed`，见[主动输出控制测评](output-control-assessments.md)。

## 运行期间复测与变化

示例的 `schedule_enabled` 为 false。显式开启后，实例运行期间会按计划主动调用指定模型或工具，间隔为 300–2592000 秒；首次在一个间隔后到期，不会在保存时立即调用。开启定时功能时，手动运行也会重设下次到期时间。一秒调度周期发现到期计划，执行运行期测评，并在执行前保存下次时间。重启后恢复计划，错过的多个周期合并为一次，不补跑全部历史，也不自动重试失败推理。

各计划独立调度，优先考虑最早到期项，因产品忙而等待的计划保持到期。全局最多两轮并行，每产品的两个计划合计最多一轮；每轮最多 16 个顺序请求，每项超时 1–30 秒，整轮最多五分钟。模型输出预算为 1–1024 tokens；工具仍限制文本为 8192 字节，取计划和工具超时的较短值，不使用模型 token 预算。这些限制不保证提供者实际计费或 token 统计方式。撤销应用、收回授权、关闭目标会阻止执行。测试请求沿用凭证策略、审计准入、传输限制及上游凭证，调用记录标为 `assessment.chat.completions` 或 `assessment.tools.invoke`，不计入生产对话／工具／输出样本数量；仍会占用全局有界审计索引的条目。

同配置的测评保留通过变失败和失败变通过的比较；版本变化后重新建立基线。远端模型或提示词在同一端点背后变化而没有登记版本时，软件不能自动识别变更。定时启动失败可查 `test-plan.last_error`，已执行的结果查 `last_run_id`。尚无外部通知、事件处置工作流或自动上线门禁。

## 留存与恢复

`test-plans.json`、`test-runs/test_*.json` 权限为 `0600`，运行记录目录为 `0700`。出站请求前先保存 `running` 记录；重启时未完成记录标为 `interrupted` / `inconclusive`。计划文件最多 256 KiB，每产品最多两个计划、全局最多 128 个，原有默认计划保持原序列化；最多留存 128 轮、每轮 512 KiB，总量上限 64 MiB。容量耗尽时停止新测评并暴露错误，不自动删除证据。应停机归档或移除旧记录，再重启。备份包含计划、运行记录、测试包、规则包及已有实例文件。

运行记录保留精确测试包、产品治理事实、规则包、执行器版本、来源版本、输入事实和评估。逐项结果含请求 ID、状态和耗时；普通模型检查另存助手文本 SHA-256。默认不保留回答正文；显式设置 `retain_responses: true` 后，在独立私有证据文件中保留每条最多 8192 UTF-8 字节的助手回答，调用日志仍无正文。输出／拒绝回执检查不保留返回正文，仅正常对照保存文本摘要。请使用合成提示词与资源，避免个人信息与秘密。提供者错误正文、上游凭证和应用密钥不会加入测试证据；测试包消息、配置资源 ID 与预期字面值始终随包快照保存。

内容摘要可以发现进程内文件变化，不是签名或防篡改存储。重放验证的是历史**确定性规则评估**，不会重跑远端模型，也无法只凭文本摘要独立重验检测器结论。记录损坏、权限不安全或版本不支持时拒绝启动，不静默丢弃历史。

## NIST AI RMF 覆盖范围

[AI RMF 1.0 官方 Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)强调部署前及运行期间测试、记录测量方法与工具，并考虑部署场景和独立审查。其范围包含 GOVERN、MAP、MEASURE、MANAGE，不是认证检查清单。来源页提示修订正在进行，本示例固定映射 **1.0（2023）**。

`nist-ai-rmf-lifecycle` 草稿只为版本化测试记录和两个阶段提供部分技术支持；场景、指标适当性、独立审查、代表性、监测与响应安排保留人工项，即使声明已有文档也不会自动通过。组织治理、风险容忍度、真实用户反馈、测试风险覆盖和人工上线决定还需要额外工作。技术测试通过不等于 NIST 认证、全面满足框架或法律合规。

## 验证

```bash
make test
make check
make build
python3 tests/active-smoke.py
```

测试使用本机模拟上游和合成资料，覆盖真实请求、两个阶段、周期调度、结果退化与未知、权限、版本隔离、私有留存、重启、重放及失败路径。真实提供者兼容性、实际产品风险测量有效性及生产规模需要另行验证。
