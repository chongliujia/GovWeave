# 产品登记与持续辅助评估

[English](../product-assessments.md) | **简体中文**

登记后的产品会将管理资料与网关自行采集的运行证据合并。保存产品、通过管理 API 修改连接／应用／密钥／凭证策略／读取工具配置、网关操作结束时，后台工作器触发重评。本功能复用[声明式引擎](compliance-engine.md)，不新增管理页面；可另行安装[有出处的欧盟透明度草案](eu-transparency-reports.md)。

## 登记与评估

1. 安装规则包并重启，配置产品应用及其模型授权或[读取工具授权](tool-governance.md)。只使用工具的应用可以采用空的模型授权列表。
2. 使用[产品示例](../../examples/product.json)，将 `application_ids` 替换为真实应用 ID，并选择已安装的 `pack_id` 和精确 `pack_version`。
3. 使用版本 `0` 提交 `POST /api/v1/compliance/products`。资料可包含用途、市场、是否面向用户等小型指标，也可引用管理员声明的文档／评估结论；服务器不会独立验证这些声明。
4. 轮询 `GET /api/v1/compliance/products/{id}/evaluation`。`state: pending` 表示没有当前结果；`ready` 包含评估；`error` 包含错误码，不返回旧的通过结果。
5. 使用当前版本调用 `PUT /api/v1/compliance/products/{id}` 更新资料。旧版本返回 `409`，不会覆盖其他更新。

所有产品接口均要求管理员会话，应用推理密钥无法访问。写入还要求 JSON、`X-GovWeave-Request: console` 和现有浏览器来源保护。

| 接口 | 行为 |
| --- | --- |
| `GET /api/v1/compliance/products` | 查询登记资料及管理事实 |
| `POST /api/v1/compliance/products` | 登记产品并触发评估 |
| `GET /api/v1/compliance/products/{id}` | 查询产品资料 |
| `PUT /api/v1/compliance/products/{id}` | 按版本保存替换资料 |
| `GET /api/v1/compliance/products/{id}/evaluation` | 查询当前结果或待评估／错误状态 |
| `POST /api/v1/compliance/products/{id}/evaluate`，请求体 `{}` | 用当前网关状态立即重评，不接受事实覆盖 |

每个产品绑定 1–64 个已存在的应用和一个精确版本的规则包。登记上限为 64 个产品，每个最多 112 个管理事实，管理请求仍限 16 KiB。名称为 1–100 个字符，产品版本遵守 [Schema](../../schemas/products.schema.json) 中的标识符格式。

## 网关证据适配器

产品资料禁止定义 `runtime.*` 或 `testing.*`，也禁止任何 `source: runtime` 的事实，该命名空间只由适配器生成。原来的无状态 `POST /api/v1/compliance/evaluations` 仍按调用者提交的事实计算，不验证来源真实性；需要服务器采集运行证据时应使用产品接口。

| 事实 | 含义 |
| --- | --- |
| `runtime.credential_policy_mode` | 当前凭证外发模式 |
| `runtime.credential_policy_revision` | 凭证策略的精确版本 |
| `runtime.gateway_revision` | 连接／应用配置版本 |
| `runtime.credential_private_key_rule_enabled` | 当前策略是否选择私钥检测规则 |
| `runtime.credential_api_key_rule_enabled` | 当前策略是否选择 API 密钥检测规则 |
| `runtime.applications_active` | 绑定的应用均存在且未撤销 |
| `runtime.credential_policy_covers_product` | 策略范围覆盖所有绑定应用及其配置的模型授权 |
| `runtime.audit_available` | 调用记录目前可可靠写入并预留结束容量 |
| `runtime.sample.request_count` | 有界样本中已结束的产品对话请求数 |
| `runtime.sample.policy_block_count` | 样本中 `error_code: policy_blocked` 的请求数 |
| `runtime.sample.observed_match_count` | 样本中凭证策略结果为 `observe` 的请求数 |
| `runtime.sample.failed_count` | 样本中结果为 `failed` 的请求数 |
| `runtime.sample.incomplete_count` | 重启后被恢复为未完成的样本请求数 |

范围覆盖使用应用的完整配置授权列表，包括已关闭的连接和已撤销的应用。应用／连接缺失或应用没有模型授权时，覆盖保持未知，不会将空授权当作已受保护。范围、模式和启用规则是独立事实：覆盖并不证明已阻断或能检出所有敏感数据；应用有效也不证明上游可用。

样本先取**全局最新 100 个索引请求条目**，再筛选该产品的应用及对话操作。它不是每个产品各取 100 条、时间窗口、完整历史或吞吐统计。进行中的请求不计入已结束数；记录不可用时省略样本计数，使依赖这些事实的要求保持未知。零只表示这个有界样本中没有观察到，并不表示从未发生。

适配器只读取配置、策略和仅含元数据的调用记录，不读取提示词／回答，也不将上游凭证、应用密钥、请求头、模型 URL、命中文本或原始上游错误写入报告。运行事实时间表示读取当前配置／样本的时刻；证据 ID 引用配置版本或审计文件字节位置，不是防篡改签名。

## 受控读取工具证据

工具治理复用产品登记、评估器、自动刷新与显式报告接口。绑定应用 ID，并选择版本 `1.0.0` 的[读取工具示例规则包](../../examples/rule-packs/read-tool-governance.json)。它是用于有界技术检查的 `internal_policy` 草案，不是法律、经过审阅的合规目录或认证。[工具产品示例](../../examples/read-tool-product.json) 不包含管理事实；此规则包使用的事实全部由服务器采集。

| 事实 | 含义 |
| --- | --- |
| `runtime.tools.revision` | 本次评估使用的全局工具存储修订号 |
| `runtime.tools.granted_tool_count` | 至少有一个资源授权给绑定应用的不同启用工具数 |
| `runtime.tools.applications_covered` | 每个已知的绑定应用都至少拥有一个启用工具的资源授权 |
| `runtime.tools.output_blocking_covers_product` | 所有绑定应用均有授权，且所有启用的已授权工具都使用 `block` 输出模式 |
| `runtime.tools.sample.request_count` | 绑定应用已结束的 `tools.invoke` 请求数 |
| `runtime.tools.sample.completed_count` | 记录结果为 `completed` 的工具请求数 |
| `runtime.tools.sample.authorization_denied_count` | 提供方执行前以 `tool_not_allowed` 拒绝的请求数 |
| `runtime.tools.sample.output_block_count` | 执行后、文本释放前以 `tool_output_blocked` 拒绝的请求数 |
| `runtime.tools.sample.observed_release_count` | 已完成且放行旧凭证规则命中的工具请求数（含仅脱敏联系方式而保留凭证的情况），不计仅有指令观察的请求 |
| `runtime.tools.sample.failed_count` | 记录结果为 `failed` 的工具请求数 |
| `runtime.tools.sample.cancelled_count` | 记录结果为 `cancelled` 的工具请求数 |
| `runtime.tools.sample.incomplete_count` | 重启后恢复为未完成的工具请求数 |
| `runtime.tools.sample.output_checked_count` | 已结束、已尝试上游调用，且输出发现为 `observed` 或 `not_observed` 的请求数 |
| `runtime.tools.sample.unknown_output_count` | 已结束、已尝试上游调用，且输出发现未知、缺失或不受支持的请求数 |

工具覆盖不会把没有授权视为受保护：已知应用缺少启用资源授权时，覆盖为假；绑定应用缺失时，覆盖保持未知。覆盖描述授权，`runtime.applications_active` 独立检查应用是否仍有效。敏感级别标签不授予访问权，无关或已关闭的工具不计入启用的已授权工具。这些事实不会改变已有的模型策略事实或对话请求计数。

工具计数使用**同一批全局最新 100 个索引请求条目**，再筛选产品应用与 `tools.invoke`，不是每个工具或产品独享的 100 条。进行中条目不计入已结束请求。审计不可用时省略样本计数，依赖项保持未知，不填零。计数不包含资源 ID 或文本。其他应用或操作的高流量会将较旧的工具证据挤出当前样本。

示例规则包要求应用有效、资源授权覆盖完整、全部启用的已授权工具配置阻断、审计容量可用、至少有一次已检查输出，以及当前有界样本中没有已观察到的凭证释放、未知输出或未完成调用。实际输出检查要求可以防止一个从未执行输出检查的配置仅凭“事件数为零”就通过。拒绝越权请求或成功扣留凭证输出说明相应控制生效，这两种情况本身不会导致规则包失败。

把工具从 `observe` 改回 `block` 会修复当前配置事实，**不会**删除之前的观察模式释放记录：该记录仍在样本中时，`TOOL-SAMPLE-RELEASES` 仍失败。之后流量将其挤出样本时，当前样本就不再描述这个旧事件；显式归档的报告仍保留原证据与结果。不能把后续干净样本当作事件被抹除，或所有历史流量均安全的证明。规则包本身不检查检索文本、不证明通用语义安全，也不自动配置运行时阻断。

安装与登记命令见[工具接入指南](tool-governance.md#产品评估与保留报告)。`make demo-agent` 演示允许和拒绝 Agent 调用、管理员主动切换观察模式、恢复阻断，以及不再执行工具的历史报告重放。调用提议与提供方响应均为脚本化样例，无需真实模型或外部 API 密钥。

## 时效、失败与生命周期

[敏感输出技术控制包](sensitive-output-governance.md)连接配置覆盖、已选类别、当前策略执行证据和有界模型／工具放行记录，指南列出了 `runtime.output_*` 与 `runtime.sample.output_*` 字段。策略修订变化会使评估失效，新修订需要自己的执行证据；过去的放行仍保留在有界样本中。

事件通知采用不阻塞模型请求的合并信号。工作器通常等待 250 毫秒合并突发变更，再评估当前状态；工作期间的新通知会触发下一轮。另外每 30 秒重评一次，覆盖到期等时间变化。这些是调度间隔，不是端到端延迟承诺。

结果记录产品、网关、策略和工具存储版本、审计字节位置／可用性、规则包摘要及评估时间。即使模型配置没有变化，工具配置变更也会使缓存失效。发布前再次检查来源快照，持续变化时最多重试三次，手动重评可能返回 `429 assessment_busy`。规则包在重启时被移除等错误会明确显示 `state: error`，不会自动替换为其他版本。工具修订号为零，或报告归档于工具证据功能加入之前时，`snapshot.tool_revision` 可以缺省；字段缺失不代表当前工具覆盖成立。

读取缓存时检查来源版本、最长 30 秒的刷新期限，以及更早的已知 `reevaluate_at` 边界：证据过期、未来证据变为当前、规则证据时效或规则包生效时间。失效结果返回 `pending`，**不附带旧评估内容**，并触发刷新。控制项缺口仍是技术评估，响应保持 `evaluation_only: true` 和 `legal_compliance: not_determined`。

资料以 `0600` 权限原子保存到 `products.json`，最大 4 MiB。写入失败保留原资料，状态损坏／版本不支持／权限不安全时拒绝启动。管理事实值会作为产品资料明确持久化，请勿把提示词、秘密或个人数据当作治理指标提交。备份应同时包含该文件和规则包。

目前只保存最新产品资料。**自动产生的最新状态有界保存在内存**，重启后依据资料和当前网关状态重新计算。独立的[显式报告保存](eu-transparency-reports.md)可将历史快照写盘，周期性评估不会归档每次结果。资料历史、独立文档验证、外部证据适配器、多包聚合、告警和法规包执行仍待建设。原有凭证策略继续独立执行其模式和范围。部署前及周期性主动测试现见[主动测评](active-assessments.md)，其合并测试证据的评估保存在独立测试记录中。当前有效输出控制测试的两项 `testing.output.*.passed` 事实也会进入产品评估与报告快照，见[主动输出测评](output-control-assessments.md)。

`go test -race ./...` 覆盖登记、适配器、事件更新和时效；构建后运行 `python3 tests/compliance-smoke.py`，可验收真实临时实例、虚构阻断请求、策略变化、资料持久化和重启重评，不访问上游模型。
