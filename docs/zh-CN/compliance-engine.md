# 声明式合规评估引擎

[English](../compliance-engine.md) | **简体中文**

GovWeave 支持本地通用技术控制评估引擎，通过 JSON 规则包扩展适用条件、要求和证据规则。规则包不执行代码。首版仅提供后端能力，与模型请求路径中的凭证策略独立。

## 安装规则包

将 JSON 包直接放入 `<data_dir>/rule-packs/`，重启后加载。不同文件名、不同 `(id, version)` 可以并存，无需重编译、下载依赖或连接云端。目录不存在时返回空目录列表；运行期间文件修改不影响已加载规则。

示例部署使用 `./data`：

```bash
mkdir -p data/rule-packs
cp examples/rule-packs/demo-ai-governance.json data/rule-packs/
go run ./cmd/govweave -config examples/deployment.json
```

原有 `demo-ai-governance` 包是 **`review.status: draft` 的虚构内部策略演示**，不是法规解释、生产控制目录或认证。它检查来自评估的 AI 告知指标，以及来自运行配置的凭证阻断模式和产品覆盖指标。仅启用阻断模式不能证明范围覆盖了产品，也不能证明所有敏感数据都能检出。

最多加载 32 个 JSON 包，每个 256 KiB，目录总条目最多 64 个。包文件为符号链接、JSON 损坏、存在未知字段、Schema 不支持、标识重复或表达式无效时拒绝启动。每包最多 64 个控制项、512 个表达式节点、嵌套深度 8。目前没有热加载、市场、远程安装器或上传 API。

## 规则包契约

[敏感输出技术控制包](sensitive-output-governance.md)草案提供八项基于服务端证据的模型／工具输出检查，包括当前修订的实际执行和样本中保留的问题。可以单独安装；加载规则包不会自动开启阻断或脱敏。

参见[示例包](../../examples/rule-packs/demo-ai-governance.json)与 [JSON Schema](../../schemas/compliance.schema.json)。每包包含：

- `schema_version`、稳定 `id`、`version`、展示名称与 `framework_kind`，区分内部策略、法律、法规、标准、自愿框架。
- `sources` 标明标题和来源版本；外部框架要求 HTTPS 来源链接。引擎不会访问这些链接。
- `review` 记录草稿或已审核状态；已审核状态要求审核人和时间。这是维护者声明，不是经过验证的签名，也没有内置审批流程。草稿允许评估，所有包目前都只提供辅助评估。
- 可选 `effective_from`、`effective_to`：起点包含、终点不包含。法律适用日期由规则包维护者核对。
- 控制项的稳定 ID、标题、条款引用、严重程度、可选 `applies_when` 与必需 `requirement`。

表达式支持 `all`、`any`、`not`，以及 `exists`、`eq`、`neq`、`in`、`gt`、`gte`、`lt`、`lte`。条件可要求证据来源为 `declared`、`runtime`、`document`、`assessment`。`max_age_seconds` 可约束时效（1–31536000；省略或 0 不限制年龄）。`in` 包含 1–32 个同类型标量；大小比较只接受数字。数字 JSON 最多 64 个字符、指数 -100 至 100，按精确有理数比较。

例如：

```json
{
  "fact": "runtime.credential_policy_mode",
  "operator": "eq",
  "value": "block",
  "source": "runtime",
  "max_age_seconds": 300
}
```

现有条件能表达的新要求可直接作为数据添加。若新法规要求新的检测器、外部服务、文档解读或当前没有的证据，则需要补充经过审核的采集适配器或引擎能力。不能把法规原文放入 JSON 后就认为已经实现可靠检测。

## 产品评估

以下接口要求管理员会话，应用推理密钥无法访问：

| 接口 | 用途 |
| --- | --- |
| `GET /api/v1/compliance/packs` | 查询已安装版本、框架类型、审核状态、控制项数量及内容摘要 |
| `POST /api/v1/compliance/evaluations` | 使用明确版本，对提交的产品事实进行评估 |

POST 使用 JSON、`X-GovWeave-Request: console`，并遵守现有来源校验。请求上限 16 KiB、160 个事实，并发评估最多 64 个，超限返回 `429 compliance_busy`。格式见[示例请求](../../examples/compliance-evaluation.json)：提交产品 ID／版本，以及每个事实的标量 `value`、`evidence_id`、`source`、`observed_at` 和可选 `expires_at`。

事实应是小型治理指标，不应提交提示词、回答、凭证或文档正文。**所有事实值及来源标签都由调用方提交，API 不独立验证其真实性。** 可信采集器与文档审查负责建立证据。示例故意缺少告知评估证据，整体预期为 `insufficient_evidence`。

评估使用服务器当前 UTC 时间。缺失、过期、超过规则时效、来自未来、类型不符或来源不符的证据均保持未知；`not` 不会把未知变成通过。`all` 的已知假分支、`any` 的已知真分支可决定逻辑结果，其他已检查分支的问题仍保留。

| 控制项状态 | 含义 |
| --- | --- |
| `pass` | 提交的证据满足该技术要求 |
| `fail` | 提交的证据与该技术要求冲突 |
| `unknown` | 无法根据有效证据确定适用性或是否满足要求 |
| `not_applicable` | 明确的适用条件不成立，或规则包不在生效时间内 |

整体状态依次优先为：存在失败则 `gaps_detected`；否则存在未知则 `insufficient_evidence`；否则存在通过则 `satisfied`；其余为 `not_applicable`。需同时查看每项结果，已知缺口不会消除其他未知要求。所有响应固定 `evaluation_only: true`、`legal_compliance: not_determined`，技术检查全部通过也不会生成整体法律合规结论。

## 实时集成与证据边界

产品资料、运行配置或证据变化时可调用 API 重新评估。执行过程完全本地、确定性，不调用 LLM 或临时检索法规；尚无经过验证的延迟 SLA。

登记后的产品现已支持[网关证据采集和自动重评](product-assessments.md)，将保存的管理资料与当前网关配置、有界请求样本结合。本页的无状态接口仍评估调用者提交的证据。另提供[显式报告快照与窄范围欧盟透明度草案](eu-transparency-reports.md)。独立文档验证和法规包运行时阻断尚未实现；原有凭证外发策略继续独立配置。

结果包含产品版本、包版本、解析后规则包的 SHA-256、审核状态、评估时间、条款引用、证据引用及问题码，不返回事实值。无状态引擎不将事实或报告写盘；独立的显式保存 API 会将治理事实值、精确规则和结果保存为私有快照，以便重放。同版本文件被修改后，重启会得到不同摘要。摘要标识内容，不提供签名；只有显式保存时才留存历史输入。实例备份应包含规则包。

规则包应区分约束性法律与自愿指南：[欧盟委员会将 AI Act 描述为基于风险的框架](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)，[NIST 将 AI RMF 定义为自愿框架](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10)。这两项来源均不是现成的 GovWeave 法规包。正式法规包需要有出处、有版本、经过人工审核的映射；不同法律可能需要多个包及新的证据能力。

执行 `make build` 后运行 `python3 tests/compliance-smoke.py`，可验收真实二进制、插件加载与 API。该测试只使用 Python 标准库、临时实例和虚构事实，不连接外部模型或法规服务。
