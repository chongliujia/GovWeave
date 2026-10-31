# 留存风险证据

[English](../risk-evidence.md) | **简体中文**

GovWeave 可以按应用范围留存证据，用于调查实际观察到的模型调用、受控只读工具调用或独立内容评估。“风险证据”页面将调用记录、捕获对象、策略快照和已有检测器发现关联起来，另用关系图展示已留存的关联。这提供可检查的证据，不自动产生风险概率、法律结论，也不完整重建 Agent 任务。

## 两条证据路径

普通 `calls.jsonl`、诊断日志和追踪响应仍只包含元数据。经显式授权的正文保险库，**仅在这个独立、需主动启用的存储中**扩展此前“不保存正文”的边界。捕获默认关闭；开启捕获不会启用检测器，也不会改变策略决策。

| 路径 | 留存内容 | 何时可用 |
| --- | --- | --- |
| 产品报告 `runtime_evidence` | 数值运行事实对应的精确应用范围审计记录和请求 ID，不含正文 | 审计可用时的新报告；保险库关闭也可用 |
| 保险库 `metadata` | 调用元数据、对象大小、带密钥指纹及可取得的策略快照 | 显式选中的应用及后续准入的捕获 |
| 保险库 `full` | 同样的元数据，以及符合限制的 UTF-8 正文 | 显式选中的应用；是否真正保留正文需查看对象状态 |

捕获独立于调用授权和已有持久化审计关卡。补充捕获失败或保险库已满，不会把已准入的模型调用改成失败，也不会削弱策略执行；相应证据保持不可用。缺失表示未知，不能证明安全。捕获要求存在匹配且已提交的终态审计记录；从请求 ID 推导出证据 ID，并不能证明证据包实际存在。

## 显式配置捕获

在“风险证据”中展开留存设置，选择 `metadata` 或 `full`，明确选择应用后保存。空应用列表永远不表示全部应用；启用模式至少需要一个已存在的应用。新应用不会自动加入。请求在身份重新校验后冻结捕获配置；后续设置修改影响后续捕获，不改变已准入捕获的模式或到期时间。关闭捕获不会删除已有证据，也不阻止管理员访问尚未到期的对象。

| 限制 | 已实现值 |
| --- | --- |
| 初始模式 | `disabled` |
| 应用范围 | 启用时明确选择 1–64 个 ID，无通配符 |
| 留存时间 | 默认 30 天；允许自捕获时起 1–365 天 |
| 每个对象保留的字节数 | 默认 64 KiB；可配置 4 KiB–1 MiB |
| 每次捕获对象数 | 最多 4 个 |
| 单个输出对象观察到的 SSE 字节 | 最多 64 MiB；仍受当次冻结的单对象正文留存上限约束 |
| 每个对象的 SSE 帧清单 | 仅前 128 帧；明确记录总数与截断状态 |
| 每次捕获策略快照 | 最多 8 个，序列化快照内容合计最多 64 KiB |
| 留存捕获总量 | 最多 2,048 份；密文文件总计最多 256 MiB |
| 单个密文文件 | 最多 6 MiB |
| 证据列表 | 默认 50、最多 100 条，最新在前，无分页游标 |
| 访问日志 | 最多 8 MiB；API 从内存保留的最近 128 个事件中返回所请求的 1–100 条 |
| 关系图 | 所选应用和根追踪内最多 32 份留存捕获 |

超过单对象限制时省略正文，不截断留存。每份摘要和证据包记录当次冻结的 `max_content_bytes`，解释留存对象时应查看该值，而不是当前配置。这个限制约束留存，独立于网关请求／响应准入上限。容量满时不会淘汰尚未到期的证据。完整捕获可能保存个人信息、机密文本及**正文内**携带的秘密，包括已被输出保护扣留、未交给调用方的文本。HTTP Authorization、Cookie、任意调用方请求头和配置中的提供方凭证不会复制进保险库。

## 理解四类对象

| 对象类型 | 含义 |
| --- | --- |
| `request` | 网关变换前已接受的应用请求正文 |
| `upstream_request` | 为实际上游尝试准备的正文；模型调用中包括替换公开别名后的提供方模型 ID |
| `upstream_output` | 输出变换或扣留前观察到的有界上游正文；SSE 对应已通过校验的完整帧 |
| `released_output` | 准备交给应用的正文，包括规范化／脱敏结果；SSE 对应纳入写入尝试的完整帧 |

并非所有阶段都会被观察到。输入被阻断时没有上游输出；输出被阻断时没有准备好的成功响应。已鉴权的授权拒绝可以留存决策元数据，但不收集未授权请求正文。无效请求、格式错误的上游响应及捕获点之前的失败，不保证有完整取证内容。`content.evaluate` 没有上游请求或响应。旧的 `streaming_not_captured` 流式输出对象继续可读，不会追溯重建正文。

逐个检查 `content_state`：`retained`、`metadata_only`、`omitted_size`、`unsupported_encoding`、`not_observed` 或 `streaming_not_captured`。指纹是按应用隔离、带密钥的已观察字节指纹；指纹相等不能证明 Agent 之间发生传输，也不是可公开复算的 SHA-256 校验和。

证据包的 `delivery_state` 为 `not_observed`、`withheld`、`release_prepared`、`write_completed`、`write_failed` 或 `stream_incomplete`。受保护输出可能在审计提交后、写入响应前捕获，因此 `release_prepared` 是有意保留的边界。对于已开始的流，`write_completed` 表示流完整结束，`write_failed` 表示实际写入／刷新失败，`stream_incomplete` 表示提前 EOF、上游错误等其他未成功结束的情况，并不宣称下游写入失败。网关写入完成，也不能证明远端客户端已经收到、理解或使用回答。

## 流式响应证据

范围内的 SSE 捕获复用现有配置、证据详情及查看正文 API。流式输出对象增加可选的 `stream` 元数据，版本为 `sse-evidence-v1`，分别记录两个阶段：

| 对象与 `stream.scope` | 字节含义 |
| --- | --- |
| `upstream_output` / `validated_frames` | 网关解析器接受的完整 SSE 帧拼接；`written_bytes` 始终为零 |
| `released_output` / `write_attempted_frames` | 纳入下游写入尝试的完整帧拼接；`written_bytes` 累计 `Write` 返回的字节数 |

这是已校验帧的观察，不是全部传输字节的录制。格式错误的帧、提供方错误帧正文及末尾不完整字节均排除。如果同一读取批次中后续帧无效，之前通过校验的帧可能进入上游证据，但整个批次在下游写入前就被拒绝。短写或写入失败时，已尝试的完整帧可能包含未报告为成功写入的字节；`Write` 成功也不证明刷新成功或客户端收到内容。

HMAC 和对象 `bytes` 覆盖该阶段所有完整已观察帧，上限为 64 MiB。`full` 模式下，只要符合条件且未超过当次冻结的 `max_content_bytes`，就保留该阶段观察到的完整帧序列，即使流以错误结束。超过上限则丢弃整个正文，包括此前缓冲的前缀，并记录 `omitted_size`；计数、HMAC 和有界帧元数据仍保留。`metadata` 模式不保留正文。因此，`content_state: retained` 也可能描述不完整流，并不代表调用完成。

`stream.frames` 只记录前 128 帧：从 1 开始的 `sequence`、该阶段拼接内从 0 开始的字节 `offset`、正整数 `bytes`、相对请求开始时间的 `elapsed_ms`，以及 `kind`（`data`、`done` 或 `other`）。`frame_count` 统计所有观察帧，超出清单上限时 `frames_truncated` 标明截断。控制台展示这份有界时间线，不自动展示正文。时间表示网关观察或尝试帧的时刻，会受读取批处理影响；它不是 token 生成耗时、提供方时间戳或可信的模型延迟测量。

| `stream.end_state` | 含义 |
| --- | --- |
| `completed` | 已观察到有效 `[DONE]`、EOF、无待处理字节，且写入和刷新均成功 |
| `incomplete_stream` | EOF 到达，但缺少要求的完整结束条件 |
| `invalid_upstream_stream` / `upstream_error` | 帧／内容校验失败或观察到提供方错误帧；出错正文不保留 |
| `response_too_large` | 流超出网关字节上限 |
| `upstream_timeout` / `upstream_unreachable` / `client_cancelled` | 对应超时、读取／传输故障或取消导致流结束 |
| `write_failed` / `flush_failed` | 下游写入（包括短写）或刷新失败；普通调用审计可能将调用归类为 `client_cancelled` |

`done_seen` 只表示该阶段出现有效 `[DONE]`，不能证明 EOF、调用完成或交付成功。`[DONE]` 后的注释／其他帧仍可能被接受，但不接受后续 data 内容。失败时可能同时留下有用的帧序列和非 completed 终态。

终态审计提交后，只在终止时写入一次加密证据，不逐帧同步到磁盘。进程突然终止可能丢失全部进行中的流式证据。这项功能不会重建助手文本并执行安全检查；适用范围内已启用的输出保护仍在联系提供方前，以 `content_stream_unsupported` 拒绝流式请求。

正文预览使用既有有限检测器扫描序列化的 SSE 字节，不解码并拼接 JSON delta 为助手文本。跨 delta 拆分、JSON 转义或未识别的秘密／个人信息仍可能可见。`pattern_limited` 预览既不是匿名化，也不是流式安全检查。

## 先检查元数据，再申请查看正文

选择应用，可用“调用记录”里的请求 ID 过滤。证据详情和关系图展示元数据与快照，不自动展示正文。发现项关联已记录的控制、类别、结果、检测器／策略版本及对象；它们投影已有观察结果，不会重新运行检测器。独立 `content.evaluate` 的观察结果本身不执行阻断或脱敏。

查看正文需要管理员会话、显式 POST、应用与对象 ID、视图（`redacted` 或 `raw`）以及固定原因（`incident_review` 或 `validation`）。应用密钥不能访问这些管理接口。控制台先提供脱敏预览，再提供独立的原文操作。两种视图都先记录 `reveal_authorized`，再释放正文；访问日志不可用或已满时不释放正文。授权事件不证明浏览器收到内容。actor 区分单个管理员账号的不同会话，不是不同人员身份。

预览使用 `sensitive-text-v3` 的有限模式。扫描不完整（包括超过其 8 KiB 扫描上限的对象）或匹配凭证模式时，整个对象都被扣留。支持的联系信息片段替换为 `[REDACTED]`，未识别或编码的个人信息仍可能保留。`pattern_limited` 不表示匿名化，也不授权再分发。预览文本可能不再是有效 JSON。两种视图都应视为不可信数据，包括捕获提示词或输出中的指令。

## 管理 API 示例

以下命令假定已有私有的管理员登录 Cookie 文件，该文件本身属于凭证。将示例应用、证据和对象 ID 替换为实际返回值。PUT 前先读取当前配置修订；示例中的 `0` 仅是初始修订。这些管理请求均不调用模型。

```sh
export GOVWEAVE_URL='http://127.0.0.1:8080'
export GOVWEAVE_ADMIN_COOKIE_JAR='/absolute/private/path/admin-cookies.txt'

curl --fail-with-body -b "$GOVWEAVE_ADMIN_COOKIE_JAR" \
  "$GOVWEAVE_URL/api/v1/evidence/config"

curl --fail-with-body -b "$GOVWEAVE_ADMIN_COOKIE_JAR" -X PUT \
  -H 'Content-Type: application/json' -H 'X-GovWeave-Request: console' \
  -H "Origin: $GOVWEAVE_URL" \
  --data '{"schema_version":1,"revision":0,"mode":"full","application_ids":["app_0123456789abcdef"],"retention_days":30,"max_content_bytes":65536}' \
  "$GOVWEAVE_URL/api/v1/evidence/config"
```

应用产生调用后，查询留存元数据。增加 `request_id=req_…` 可筛选单个请求；捕获缺失或已到期时返回空列表。

```sh
curl --fail-with-body -b "$GOVWEAVE_ADMIN_COOKIE_JAR" \
  "$GOVWEAVE_URL/api/v1/evidence?application_id=app_0123456789abcdef&limit=20"

curl --fail-with-body -b "$GOVWEAVE_ADMIN_COOKIE_JAR" \
  "$GOVWEAVE_URL/api/v1/evidence/ev_0123456789abcdefghijkl?application_id=app_0123456789abcdef"

curl --fail-with-body -b "$GOVWEAVE_ADMIN_COOKIE_JAR" \
  "$GOVWEAVE_URL/api/v1/evidence/ev_0123456789abcdefghijkl/graph?application_id=app_0123456789abcdef"

curl --fail-with-body -b "$GOVWEAVE_ADMIN_COOKIE_JAR" -X POST \
  -H 'Content-Type: application/json' -H 'X-GovWeave-Request: console' \
  -H "Origin: $GOVWEAVE_URL" \
  --data '{"application_id":"app_0123456789abcdef","object_id":"ev_0123456789abcdefghijkl:upstream_output","view":"redacted","reason":"incident_review"}' \
  "$GOVWEAVE_URL/api/v1/evidence/ev_0123456789abcdefghijkl/reveal"
```

查看响应包含 `evidence_id`、`object_id`、`view`、`text` 和 `redaction_state`；上述命令会将内容打印到终端。请求 `view: raw` 是独立的特权披露。`GET /api/v1/evidence/access?limit=20` 读取访问元数据。`POST /api/v1/evidence/purge` 携带 `{}`，只删除到期捕获并返回 `expired_records_removed`。GET 过滤参数拒绝重复、未知或空值，查询字符串最多 512 字节。

| 响应 | 含义 |
| --- | --- |
| `400 invalid_evidence_request` | 配置、范围、查询或查看字段无效 |
| `401` | 需要管理员会话 |
| `404 evidence_not_found` | 所选应用没有该留存捕获；其他应用的 ID 不赋予访问权 |
| `409 evidence_content_unavailable` | 该对象未保留正文 |
| `409 revision_conflict` | 保存前刷新当前配置修订 |
| `410 evidence_expired` | 留存期已结束；尚未物理删除也拒绝直接读取 |
| `503 evidence_unavailable` | 无法验证或写入证据／访问日志 |
| `507 evidence_capacity` | 有界存储或访问日志没有剩余容量 |

精确契约见 [OpenAPI](../../api/openapi.yaml) 和[证据 Schema](../../schemas/evidence.schema.json)。

## 关系图和报告边界

关系图将留存调用与对象、策略快照和发现关联起来。如果根对象有追踪 ID，则纳入**同一个应用**里该追踪最多 32 份留存捕获。即使目标可见，parent、link、retry 边仍属于 `caller_declared`。缺失目标保持 `unresolved`，重复 span 匹配为 `ambiguous`。不根据内容相似性或指纹推断边，也不跨应用关联正文。`history_may_be_missing` 始终为 true，`graph_complete` 始终为 false；应检查 `result_truncated` 和 `unavailable_records`。原有 [Agent 追踪视图](agent-tracing.md)仍是独立的元数据视图，使用全局最近 1,000 个请求索引。

审计可用时，新产品报告加入可选 `runtime_evidence`。其中 `records` 是从**全局最近 100 条审计记录**中按产品应用筛出的精确模型／工具记录，不是每个应用各 100 条。每个数值事实列出考虑过的 `source_request_ids` 和实际计数的 `matched_request_ids`。`audit-bytes-…` 等运行证据 `evidence_id` 是来源标记，不是保险库 `ev_…` ID。显式归档报告会保留这些样本与引用，实时窗口移动后仍可检查；捕获关闭时也可用。旧报告没有该字段仍可重放。归档可用性、窗口大小与部分观察仍限制结论。详见[产品测评](product-assessments.md)和[报告快照](eu-transparency-reports.md)。

## 跨应用任务证据

控制台的“跨应用任务证据”将同一追踪中的留存证据与近期审计元数据合并展示。输入追踪 ID，明确选择 1–16 个已存在的应用，再点击“加载任务证据”。单份证据上的“跨应用查看此任务”只预填其追踪 ID 和所属应用，其他应用需主动添加。查询不会启用采集、授予应用权限或展示正文。

此接口仅允许管理员会话访问，通过重复且不相同的 `application_id` 指定范围：

```sh
curl --fail-with-body -b "$GOVWEAVE_ADMIN_COOKIE_JAR" \
  "$GOVWEAVE_URL/api/v1/evidence-traces/1234567890abcdef1234567890abcdef?application_id=app_0123456789abcdef&application_id=app_fedcba9876543210&limit=128"
```

`limit` 默认 100，允许 1–128。视图先读取所选应用中最新的 `min(32, limit)` 份未到期证据，再用近期审计元数据填充剩余调用位置。审计来源在**全局最近 1,000 次请求索引**中最多选取 128 条匹配记录；证据离开此审计窗口后仍可能可见。数量限制针对整个选定范围，不是每个应用各有一份配额，也不保证历史完整。返回调用按记录时间排序；无法读取记录时使用证据创建时间。查询字符串最多 2,048 字节，拒绝未知参数、重复应用和重复 limit。合法范围内没有可见调用时返回空的 `200` 视图。

| 调用的 `evidence_state` | 含义 |
| --- | --- |
| `retained` | 证据已读取并通过认证；其中单个对象仍可能没有留存正文 |
| `not_found` | 近期审计调用在本次索引观测中没有匹配的未到期证据，原因未知 |
| `unavailable` | 匹配的索引证据无法读取、无法验证，或在查询过程中变得不可用 |
| `not_loaded` | 近期审计调用存在索引证据，但超出本次证据读取上限 |

`record_source` 区分 `retained_evidence`、`recent_audit` 和 `evidence_index`。只有索引的行省略 `record`，不会伪造执行结果。检测发现及 `summary.retained_findings` **仅来自成功读取的证据**，并不覆盖全部近期审计记录。其他状态下的空发现数组不代表无风险，控制台显示“—”。可打开可用证据，检查策略版本、采集对象并通过原有受审计入口查看内容。改变任务范围会清除上一视图和可见正文，迟到响应不能恢复旧范围。

调用作为图中的节点，父子、汇合（`link`）和重试关系只在本视图返回的记录中解析；重复 span 保持 `ambiguous`，缺失目标保持 `unresolved`。跨应用关系和 Agent ID 仍是调用方声明。共享追踪 ID 或已解析的边，都不证明交接、数据传输、根因或任务完成；此视图不比较跨应用正文指纹。原有使用应用密钥的 `/v1/traces/{trace_id}` 仍局限于已鉴权的应用。

应检查 `result_truncated`、`audit_result_truncated`、`evidence_result_truncated`、`audit_window_saturated` 和 `audit_available`。最后一项表示审计是否有能力准入新调用；它为 false 时，已有观测仍可查询。`history_may_be_missing` 始终为 true，`graph_complete` 为 false，`task_completion` 为 `not_determined`。审计和证据库分别读取，这是实时、非原子的调查视图，不是留存的报告快照。它不能重建两个存储中都已缺失的调用、延长到期留存或判定法律合规。单份证据的 `/api/v1/evidence/{id}/graph` 保持原有的同应用范围。

## 任务快照与报告导出

加载任务视图后，点击“保存此任务快照”。服务端重新执行相同的有界查询，将摘要与页面所见结果比较。如果调用、发现、证据状态或覆盖标志已变化，返回 `409 task_view_changed`；应重新加载并复核后再保存。摘要用于乐观并发检查，不是认证凭据。保存不调用模型、不修改采集设置，也不接受浏览器提交的调用记录。

使用“加载已保存快照”，以同一追踪和完全相同的应用集合查询历史结果；子集或超集均不匹配。快照在重启后、调用移出审计窗口后，以及原始正文到期后仍可读取。控制台明确标出历史结果，并显示应用 ID，不使用当前应用名称。证据可用性表示保存时的观察，不代表当前访问状态。查看当前情况需重新加载实时任务证据；历史查看不重新打开正文。

每份快照冻结任务视图中的应用范围、调用、发现引用及检测器／策略观察版本、声明关联、证据状态、数据源上限和不完整标志。它**不复制正文、完整对象清单或完整策略文档**。`created_at` 是快照保存时间，审计与证据库的观察仍分别采集；`created_by` 标识管理员会话，不代表独立识别的人。空视图也可保存，仍表示证据不足。

“导出快照 JSON”下载完整的版本化快照；精确字节（含末尾换行）与 `summary.bytes`、`summary.sha256` 及下载响应的 `X-GovWeave-SHA256` 一致。“导出 Markdown 报告（英文）”从同一快照生成确定性的英文报告，包括调用表、发现表、关联来源和覆盖限制。报告引用的是 JSON 校验值，不是 Markdown 文件的校验值。两种导出都不重新评估，也不判定法律合规。

以下管理员接口都要求显式重复传入 `application_id` 限定范围：

| 方法与路径 | 行为 |
| --- | --- |
| `POST /api/v1/evidence-traces/{trace_id}/snapshots` | 受写入保护的 JSON 请求，正文为 `{"expected_view_sha256":"…"}`；使用实时 GET 的摘要及相同 `limit`（默认 100，最多 128）；成功返回 `201` |
| `GET /api/v1/evidence-traces/{trace_id}/snapshots` | 列出与追踪／应用集合完全匹配的最多 256 份摘要，最新在前 |
| `GET /api/v1/evidence-traces/{trace_id}/snapshots/{snapshot_id}` | 校验并读取已保存元数据，不查询实时证据 |
| `GET /api/v1/evidence-traces/{trace_id}/snapshots/{snapshot_id}/export/json` | 下载完整 JSON 快照 |
| `GET /api/v1/evidence-traces/{trace_id}/snapshots/{snapshot_id}/export/markdown` | 下载英文 Markdown 报告 |

只有创建接口接受 `limit`，其他过滤参数均拒绝。应用密钥不能访问这些接口。有效但不匹配的范围或未知 ID 返回 `404 evidence_not_found`；无效查询返回 `400`；文件不可用或不安全返回 `503 evidence_unavailable`。创建／读取最多同时进行 4 个操作，超出返回 `429 task_snapshot_busy`。重复成功的 POST 会创建不同快照；保存响应丢失时，应先检查列表再重试，超时不证明保存失败。切换范围会丢弃迟到的界面响应并移除旧下载链接。

快照是保存在 `task-evidence/` 中的私有**明文元数据**，通过绑定 `evidence.key`、独立用途派生的 HMAC 密钥认证。打开／导出时校验文件；摘要列表来自索引，不代表逐份重新校验。没有密钥的内容修改、不安全权限和无效快照会被拒绝，启动时也会检查。`authenticated_local` 不构成外部存证、可信时间或完整认证清单；重启前删除整份快照仍可能无法发现。

容量独立于正文保险库：最多 256 份快照、单文件 2 MiB、合计 64 MiB。达到上限返回 `507 evidence_capacity`，不驱逐已有快照。此版本没有自动到期、轮转或快照删除 API，应监控容量并保留一致备份。保险库清理不删除任务快照或导出副本。元数据仍可能包含敏感的操作标识和关系，下载与备份应保持私有。

## 存储、到期与恢复

私有数据目录包含独立的 32 字节 `evidence.key`、加密的 `evidence/ev_….sealed` 证据包、`evidence/config.json` 和只含元数据的 `evidence/access.jsonl`。证据包使用 AES-256-GCM、随机 nonce 和绑定证据 ID 的认证数据；指纹与访问事件认证派生独立 HMAC 密钥。配置和访问元数据是私有文件，不是加密正文包。`integrity: authenticated` 表示本机密文认证，不代表外部认证、可信时间戳或观察结果正确。

目前没有外部或只写一次的校验锚点，也没有认证过的完整预期证据清单。重启前删除整个证据包，可能只表现为证据缺失；删去访问日志末尾的一段有效事件，重启后也无法独立证伪。因此，密文认证不等于防篡改或完整的取证链。

停机后备份**完整私有数据目录**，将 `evidence.key`、`evidence/`、`task-evidence/` 与现有凭证保险库文件一起保存，并把备份视为敏感数据保护。证据密钥缺失／不匹配、密文损坏、权限不安全、任务快照无效或访问日志损坏都可能导致启动失败。尚无密钥轮换、远程 KMS 或自动访问日志轮转。应恢复一致且已验证的备份，不要保留旧密文或认证快照却替换密钥。见[部署与恢复](deployment.md)。

读取时强制检查到期时间。启动、适用范围内的捕获或显式 purge 时清理到期文件；没有持续运行的到期清理任务。删除前先记录授权，失败保持可见。删除不影响备份、存储快照或此前已查看输出中的副本，也不保证物理安全擦除。普通调用日志与显式归档的元数据报告有各自的保留边界，不随保险库 purge 删除。存储决策见 [ADR 0010](adr/0010-scoped-risk-evidence.md)。
