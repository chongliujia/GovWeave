# 欧盟 AI 客服透明度草案与报告留存

[English](../eu-transparency-reports.md) | **简体中文**

本次交付将一个窄范围、有出处的法规草案与显式报告留存结合，示例面向“向欧盟用户提供 AI 客服界面的提供者”。它不自动判断整个产品的法律属性，不独立检查界面，不提供合规认证或法规执行。

## 来源与审核状态

草案选取 [AI Act 第 50(1)、50(5) 条](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-50)中的交互告知要求，涉及告知、时机、呈现及适用无障碍要求；[第 2 条](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-2)和[第 3 条](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-3)用于范围／角色复核。[第 113 条](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-113)及[欧盟委员会问答](https://digital-strategy.ec.europa.eu/en/faqs/transparency-obligations-under-article-50-ai-act)提供适用日期参考。

来源核对日期为 **2026-10-28**；官方 Service Desk 标明其文本基于 2026-07-27 合并版本。规则包以公布的 2026-08-02 适用日期设置 UTC 评估门槛，具体时间和法域适用性仍需复核。运行时不临时检索法规。

**`review.status` 为 `draft`。** 来源核对不等于法律专家审核，没有虚构审核人或审批时间。此包不覆盖第 50(2) 条生成内容标记、50(3)/(4)、高风险／GPAI 义务、GDPR 或其他法律；真实客服产品可能还有这些额外义务。

## 六个可审核控制项

| 控制项 | 方法 | 依据与边界 |
| --- | --- | --- |
| `EU50-SCOPE` | 人工 | 范围、提供者角色及例外复核；属于辅助实践，不另行声称法律要求编写某种范围文档 |
| `EU50-NOTICE` | 证据 | 第 50(1) 条的部分告知指标 |
| `EU50-TIMING` | 证据 | 第 50(5) 条的首次交互时机指标 |
| `EU50-CLARITY` | 人工 | 基于实际场景的清晰、可区分判断 |
| `EU50-ACCESSIBILITY` | 人工 | 确定适用无障碍依据并评估 |
| `EU50-RELEASE-EVIDENCE` | 证据 | 当前版本的验证材料，明确属于辅助实践，不是新增法定期限 |

`product.market`、`product.operator_role`、`product.use_case`、`product.is_ai_system`、`product.direct_interaction` 只是窄场景路由声明。`scope.article50_1_exception_claimed` 可路由告知检查，但**不会批准例外**；即使其他项目被路由为不适用，范围复核仍保持人工待办。缺少路由证据时，适用性保持未知。

证据条件读取提交的评估指标，不会打开实际产品、检查截图、执行无障碍浏览器测试或验证评估人的资格。适用的 `assessment_method: manual` 始终返回 `unknown`／`manual_review_required`，即使提交了肯定的复核指标。本版没有把解释性判断转为已验证批准的工作流。

发现项包含控制 ID、条款、依据类型、严重程度、行动建议和相关事实 ID：

- `control_gap`：提交的证据未满足技术条件，不自动等于法律违规。
- `evidence_gap`：证据缺失或不可用，无法判断。
- `manual_review`：需要人工判断或适用性复核。

每项控制保留详细问题码；每个发现项使用一个主要类别，人工复核也可能同时缺少材料。`basis: supporting_practice` 将辅助验证建议与映射的法律义务区分。结果仍保留 `evaluation_only: true` 和 `legal_compliance: not_determined`。

## 安装与验收

```bash
mkdir -p data/rule-packs
cp examples/rule-packs/eu-ai-act-chatbot-transparency.json data/rule-packs/
go run ./cmd/govweave -config examples/deployment.json
```

按部署调整数据路径。规则包 ID 是 `eu-ai-act-chatbot-transparency`，版本 `0.1.0`；[完整定义](../../examples/rule-packs/eu-ai-act-chatbot-transparency.json)包含来源、日期、边界和行动建议。管理员可通过 `GET /api/v1/compliance/packs/{id}/versions/{version}` 查看已安装定义。

创建模型连接与应用，替换[产品示例](../../examples/eu-customer-support-product.json)里的应用占位符，再通过[产品 API](product-assessments.md)登记。示例故意缺少界面证据。实际拥有相应材料后再提交当前指标，不要把示例中的范围声明当作法律结论。

虚构验收流程为：缺材料时出现证据缺口和人工复核；告知指标为否时出现控制缺口；补齐告知、时机和版本材料后，对应条件通过，但三个人工项目仍未知。这验证的是软件行为，不是真实客户界面或法律状态。

## 保存不可变报告快照

以下接口均要求管理员会话。POST 要求 JSON、`X-GovWeave-Request: console` 和现有来源保护。应用推理密钥无法读取历史产品证据。

| 接口 | 行为 |
| --- | --- |
| `POST /api/v1/compliance/products/{id}/reports`，请求体 `{}` | 重新评估并保存独立快照 |
| `GET /api/v1/compliance/products/{id}/reports` | 按保存时间倒序列出摘要 |
| `GET /api/v1/compliance/reports/{report}` | 读取历史快照和校验值 |
| `POST /api/v1/compliance/reports/{report}/replay`，请求体 `{}` | 使用保存的规则、事实和评估时间重放 |

快照保存精确产品资料／版本、完整规则包及来源元数据、输入指标、运行来源版本、引擎版本、评估时间、控制结果和整改建议。之后修改产品、替换插件、证据到期或重启，都不会替换历史输入。重放不读取当前插件目录或网关状态。引擎版本不支持时返回 `409 replay_version_unsupported`；只要 Schema 可支持，历史文档仍可读取，不能静默改用新语义。

**显式保存会持久化治理事实值**，包括管理声明和网关指标，以便复现；普通实时评估响应仍不返回这些值。适配器不复制模型请求／回答或凭证，请勿把这些内容写入管理事实。历史报告表示当时的状态，查询当前状态应使用实时评估接口。

## 存储与失败

快照保存在私有 `assessment-reports/rpt_*.json`：目录 `0700`、文件 `0600`。上限为 **256 份报告、每份 1 MiB、合计 64 MiB、8 个并发归档／重放操作**。API 不更新或删除既有快照，周期性评估不会自动填满归档。容量不足返回 `409 archive_capacity` 并保留历史，写入失败不会发布索引；辅助评估仍与网关现有审计准入独立。

启动时校验文件并重建有界索引；损坏、权限不安全、结构不一致或 Schema 不支持时拒绝加载，不静默丢弃。读取时比对当前索引中的文件摘要，支持的引擎版本还会复算结果。应将该目录与产品资料、规则及实例其他文件一致备份。

`pack_sha256` 标识序列化后的规则定义，摘要中的 `sha256` 标识归档文件的完整字节。它们**不是签名、哈希链或 WORM 存储**；有文件权限的运维人员可以改写数据，跨重启审计文件变化时需在外部保留预期摘要。

执行 `make test`、`make check`、`make build`，再运行 `python3 tests/compliance-smoke.py`。该测试仅使用临时数据和虚构证据，覆盖产品／插件更新和重启后的历史重放，不访问模型。[报告 Schema](../../schemas/reports.schema.json) 与 [OpenAPI](../../api/openapi.yaml) 定义了数据契约。
