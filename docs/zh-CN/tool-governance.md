# 面向应用与 Agent 开发者的受控只读工具

[English](../tool-governance.md) | **简体中文**

GovWeave 通过 `POST /v1/tools/{alias}/invoke` 执行已配置的读取工具。应用使用自己的应用密钥认证；GovWeave 在调用工具前检查管理员配置的资源授权，检查返回文本中的固定凭证模式，并在释放文本前持久保存最终决策。这是一条供应用后端和 Agent 平台接入的 API 流程，不需要新增前端。

首个适配器使用一个明确的小协议：读取一个已配置的资源，返回文本。它独立于 Chat Completions 中 `tools`/`tool_calls` 的 JSON 透传。要治理 Agent 的工具行为，执行器必须实际调用此端点。直接访问数据库、文件系统、MCP 服务或其他工具不会经过这里的控制。

如需在部署前与运行期主动验证资源拒绝、敏感输出保护和正常读取，使用[主动读取工具测评](tool-control-assessments.md)。其证据通过独立工具事实进入产品报告。

## 执行与决策流程

1. 验证应用密钥，检查有界请求。调用方提供的身份、授权、敏感级别、URL 或命令均作为未知字段拒绝。
2. 读取请求体后再次检查密钥，统一解析启用的工具与资源授权。未知工具、未知资源和缺少授权均返回 `403 tool_not_allowed`，不发起上游调用。
3. 在执行配置好的 HTTP 请求前，持久保存开始记录并预留审计容量。本次调用使用已接纳的不可变工具版本；后续配置编辑、密钥撤销或轮换影响之后的接纳检查。
4. 缓冲并验证完整的工具响应，对 `text` 执行 `credentials-v1` 检查（`private_key` 和 `api_key`）。`block` 模式命中时返回 `403 tool_output_blocked`，不释放文本；`observe` 模式返回文本并附带发现。响应无效或不可用时，两种模式都会阻止输出。
5. 发送任何工具文本前，保存最终元数据记录。如果最终审计写入失败，返回 `503 audit_unavailable` 并扣留文本。

响应分别给出以下证据维度：

| 维度 | 来源 | 首版行为 |
| --- | --- | --- |
| 授权 | 已认证的应用与配置的资源授权 | 缺少授权时，在执行前拦截 |
| 数据敏感级别 | 管理员分类：`public`、`internal`、`restricted` | 作为审查上下文，不独立授予或拒绝访问 |
| 动作 | 适配器固定的 `read` | 只暴露读取协议 |
| 输出凭证发现 | 编译内置的 `credentials-v1` 模式 | `block` 扣留命中输出；`observe` 返回输出和发现 |
| 证据可用性 | 协议、时间/大小限制与持久审计 | 失败时扣留输出 |

所有资源都需要显式应用授权，包括 `public` 资源。空的 `allowed_applications` 列表拒绝所有应用。管理员明确授权后，应用可以读取 `restricted` 资源。首版不计算风险概率、不自动推断敏感级别、不授权单个终端用户，也不作法律合规结论。

`not_observed` 只表示没有找到这些凭证模式，并不是通用安全结论。当前模式覆盖私钥头和部分令牌前缀，不覆盖任意秘密、通用个人信息、提示注入、有害语言、编码或混淆泄露，以及检索文档的语义正确性。离线 canary 实验没有替代这里的运行时检查。

## 上游读取协议

管理员配置完整且固定的 `endpoint`，例如 `https://retrieval.internal/read`。GovWeave 发送：

```http
POST /read
Content-Type: application/json
Accept: application/json
Authorization: Bearer <配置的上游凭证，如有>

{"resource_id":"support-handbook"}
```

提供方必须返回 HTTP `200`、`Content-Type: application/json`，且 JSON 恰好包含一个字符串字段：

```json
{"text":"Support hours are 09:00–18:00."}
```

资源 ID 通过 JSON 发送，不会插入路径。适配器不接收自由查询、写操作、命令或调用方控制的 URL。应部署实现这个只读约定的提供方；HTTP 方法本身无法证明任意上游服务没有副作用。GovWeave 仅发送配置的上游凭证及自己的固定请求头、请求 ID，不转发应用凭证、Cookie 或任意调用方请求头。

不跟随重定向，也不自动重试 POST。HTTPS 会校验证书。管理员控制的集成可使用私网或回环地址；链路本地、组播和未指定地址会被拒绝，DNS 解析时也会检查。HTTP 必须显式设置 `allow_insecure_http: true`。部署时应配合相应的网络出口控制。

## 配置与调用

管理接口使用已有且已认证的管理员 Cookie 文件。请将其和生成的密钥文件保存在私有位置。`GOVWEAVE_ROOT` 是服务根地址，不带 `/v1`；`GOVWEAVE_COOKIE_JAR` 是私有 Cookie 文件路径。下面示例仅使用 Python 3 组装 JSON 和读取返回 ID。

创建一个只使用工具的应用。空的模型授权列表不会授予任何模型访问权限：

```bash
umask 077
curl --fail-with-body "$GOVWEAVE_ROOT/api/v1/applications" \
  --cookie "$GOVWEAVE_COOKIE_JAR" \
  -H 'X-GovWeave-Request: console' -H 'Content-Type: application/json' \
  --data '{"name":"Support agent","allowed_connections":[]}' > application.json
export GOVWEAVE_APP_ID="$(python3 -c 'import json; print(json.load(open("application.json"))["application"]["id"])')"
export GOVWEAVE_API_KEY="$(python3 -c 'import json; print(json.load(open("application.json"))["api_key"])')"
```

密钥只在创建或轮换时返回，应保存在应用后端的密钥管理系统中。它不能访问管理接口；管理员会话也不能调用工具。

读取当前工具存储修订号，配置本地示例提供方。`revision` 使用本次 GET 返回的全局工具修订号，不是网关配置修订号，也不是某个工具自己的修订号：

```bash
curl --fail-with-body "$GOVWEAVE_ROOT/api/v1/tools" \
  --cookie "$GOVWEAVE_COOKIE_JAR" > tools-current.json
export GOVWEAVE_TOOL_ENDPOINT='http://127.0.0.1:8001/read'
python3 - <<'PY'
import json, os
config = {
    "revision": json.load(open("tools-current.json"))["revision"],
    "name": "Support retrieval",
    "alias": "support",
    "endpoint": os.environ["GOVWEAVE_TOOL_ENDPOINT"],
    "enabled": True,
    "allow_insecure_http": True,
    "timeout_seconds": 5,
    "output_mode": "block",
    "resources": [{
        "resource_id": "support-handbook",
        "sensitivity": "internal",
        "allowed_applications": [os.environ["GOVWEAVE_APP_ID"]],
    }],
}
with open("tool.json", "w") as output:
    json.dump(config, output)
PY
curl --fail-with-body "$GOVWEAVE_ROOT/api/v1/tools" \
  --cookie "$GOVWEAVE_COOKIE_JAR" \
  -H 'X-GovWeave-Request: console' -H 'Content-Type: application/json' \
  --data-binary @tool.json > tool-saved.json
```

请把端点替换为实际可访问的读取服务。上面的 HTTP 显式开关用于本地示例；需要加密连接时使用 HTTPS。如果提供方需要认证，在私有配置输入中增加其 `api_key`。响应与历史只暴露 `has_credential`。更新时，省略 `api_key` 或设为 `null` 会保留原凭证，空字符串则清除凭证。

应用或 Agent 执行器需要该资源时，调用：

```bash
curl --fail-with-body "$GOVWEAVE_ROOT/v1/tools/support/invoke" \
  -H "Authorization: Bearer $GOVWEAVE_API_KEY" \
  -H 'Content-Type: application/json' \
  --data '{"resource_id":"support-handbook"}'
```

成功响应包含 `request_id`、`text` 和 `governance`。后者包含 `policy_version: read-tool-governance-v1`、`ruleset_version: credentials-v1`、工具版本和哈希、各证据维度、最终的 `allow` 或 `observe` 决策，以及固定原因代码。只有成功响应才能使用 `text`。错误响应包含 `error` 和治理证据，不包含提供方文本；不要绕过治理端点重新执行已拦截动作。

Agent 平台可以暴露一个仅接收 `resource_id` 的读取工具，并使用此 HTTP 请求实现工具执行器。应用密钥绑定在服务端，不让模型提供或选择密钥、端点、应用 ID 或授权。应用级隔离不等于终端用户的委托授权；需要使用不同的应用与授权表示本版支持的隔离边界。

## Python 参考客户端

基于标准库的[参考客户端](../../examples/python/govweave_tools.py) 可以复制到应用中，也可从 `examples/python` 导入。它是可运行的示例，不是已发布的 GovWeave SDK 安装包。`GovernedToolClient(root_url, api_key, alias, timeout=5, allow_insecure_http=False)` 在后端代码中绑定服务地址、应用身份和配置好的别名。`invoke(resource_id)` 与 `execute({"resource_id": ...})` 返回含 `text`、`request_id`、`governance` 的 `ToolResult`。

沿用前面的环境变量进行本地调用：

```bash
export GOVWEAVE_TOOL_ALIAS='support'
python3 examples/python/read_resource.py support-handbook --allow-insecure-http
```

CLI 需要 `GOVWEAVE_ROOT`、`GOVWEAVE_API_KEY` 和 `GOVWEAVE_TOOL_ALIAS`。默认只打印请求 ID 与治理决策；显式增加 `--show-text` 才会打印检索文本。HTTPS 部署不需要 `--allow-insecure-http`。客户端不跟随重定向、不继承环境变量代理、不重试请求，也不会回退到绕过治理的端点。

Agent 执行器可以使用相同接口：

```python
import os
from govweave_tools import GovernedToolClient, ToolCallError

client = GovernedToolClient(
    os.environ["GOVWEAVE_ROOT"],
    os.environ["GOVWEAVE_API_KEY"],
    os.environ["GOVWEAVE_TOOL_ALIAS"],
    timeout=10,
    allow_insecure_http=True,  # 本地 HTTP 示例的显式许可。
)
arguments = {"resource_id": "support-handbook"}  # 已解析的工具参数。
try:
    result = client.execute(arguments)
except ToolCallError as error:
    print({"error_code": error.code, "request_id": error.request_id})
else:
    # 将 result.text 交给预期的应用流程，避免写入日志。
    print({"request_id": result.request_id, "governance": result.governance})
```

运行时将 `examples/python` 放入 Python 模块路径，或把参考模块复制到自己的项目。`execute` 只接受资源 ID 字段；额外的身份、URL 或授权字段在本地返回 `invalid_arguments`。服务器拒绝会产生 `ToolCallError`，提供固定的 `code`、`request_id` 和 `http_status`。无效或不支持的响应契约会被拒绝。`observe` 模式属于成功响应，可能同时包含凭证发现和文本，应用需自行决定如何处理。客户端超时范围为 1–60 秒，通过套接字超时和读取响应体时的已用时间检查执行。应在提供方截止时间之外为本地检查留出余量；它不是绝对的 DNS 或整个进程延迟保证。

## 产品评估与保留报告

工具决策现在通过服务器拥有的配置和审计事实接入已有产品评估器。将[读取工具技术控制规则包](../../examples/rule-packs/read-tool-governance.json) 安装到实例的规则包目录。以数据目录 `./data` 为例：

```bash
mkdir -p data/rule-packs
cp examples/rule-packs/read-tool-governance.json data/rule-packs/
```

重启服务以加载规则包，然后重新建立管理员会话和 Cookie 文件。规则包 ID 为 `read-tool-governance`，版本 `1.0.0`，属于内部策略**草案**。它要求应用有效、启用资源授权覆盖完整、全部启用的已授权工具阻断输出、审计容量可用、至少有一次已检查输出，以及当前有界样本中没有已观察到的凭证释放、未知输出或未完成调用。这些技术检查不构成法律合规结论。

使用[工具产品模板](../../examples/read-tool-product.json) 登记前面创建的应用：

```bash
umask 077
python3 - <<'PY'
import json, os
product = json.load(open("examples/read-tool-product.json"))
product["application_ids"] = [os.environ["GOVWEAVE_APP_ID"]]
with open("read-tool-product.json", "w") as output:
    json.dump(product, output)
PY
curl --fail-with-body "$GOVWEAVE_ROOT/api/v1/compliance/products" \
  --cookie "$GOVWEAVE_COOKIE_JAR" \
  -H 'X-GovWeave-Request: console' -H 'Content-Type: application/json' \
  --data-binary @read-tool-product.json > product-saved.json
export GOVWEAVE_PRODUCT_ID="$(python3 -c 'import json; print(json.load(open("product-saved.json"))["id"])')"
curl --fail-with-body "$GOVWEAVE_ROOT/api/v1/compliance/products/$GOVWEAVE_PRODUCT_ID/evaluate" \
  --cookie "$GOVWEAVE_COOKIE_JAR" \
  -H 'X-GovWeave-Request: console' -H 'Content-Type: application/json' --data '{}'
```

资料故意不提交运行事实，调用方不能设置 `runtime.*`。实际工具调用和配置变化会触发后台重评。新配置若在当前样本中还没有任何已检查输出，会在输出证据控制上失败，因此仅打开阻断开关不能让全部控制通过。拒绝越权请求或正确扣留凭证输出，本身不会导致控制失败。

查看 `controls`、`findings` 和整体技术状态。响应仍包含 `evaluation_only: true` 和 `legal_compliance: not_determined`。工具事实来自配置，以及**全局最新 100 个**索引请求条目中属于绑定应用且操作为 `tools.invoke` 的记录；它不是完整历史，也不是产品独享的 100 条窗口。审计失败时，样本事实缺失并保持未知。全部事实及其边界见[产品证据说明](product-assessments.md#受控读取工具证据)。

需要保留证据时，显式保存报告：

```bash
curl --fail-with-body "$GOVWEAVE_ROOT/api/v1/compliance/products/$GOVWEAVE_PRODUCT_ID/reports" \
  --cookie "$GOVWEAVE_COOKIE_JAR" \
  -H 'X-GovWeave-Request: console' -H 'Content-Type: application/json' --data '{}' > report-saved.json
export GOVWEAVE_REPORT_ID="$(python3 -c 'import json; print(json.load(open("report-saved.json"))["summary"]["id"])')"
curl --fail-with-body "$GOVWEAVE_ROOT/api/v1/compliance/reports/$GOVWEAVE_REPORT_ID/replay" \
  --cookie "$GOVWEAVE_COOKIE_JAR" \
  -H 'X-GovWeave-Request: console' -H 'Content-Type: application/json' --data '{}'
```

重放使用保留的规则包、事实值和评估时间，不会调用工具或重新验证在线输出。报告保存技术元数据与指标；适配器不复制资源 ID、端点、凭证或检索文本。重放历史报告不代表当前应用仍处于相同状态。

## 管理、历史与审计

| 端点 | 认证 | 结果 |
| --- | --- | --- |
| `GET /api/v1/tools` | 管理员会话 | 当前工具存储修订号及元数据 |
| `POST /api/v1/tools` | 管理员会话与写入请求头 | 创建工具；`201` |
| `PUT /api/v1/tools/{id}` | 管理员会话与写入请求头 | 使用当前全局修订号替换配置；`200` |
| `GET /api/v1/tools/{id}/history` | 管理员会话 | 不可变元数据快照，最新版本优先 |
| `POST /v1/tools/{alias}/invoke` | 应用 Bearer 密钥 | 执行已接纳的读取动作 |
| `GET /api/v1/requests?application_id=...` | 管理员会话 | 最近元数据记录，包含 `tools.invoke` |

管理写入需要 `X-GovWeave-Request: console` 和 JSON，使用已有来源检查，陈旧修订号返回 `409 revision_conflict`。保存时资源授权只能引用已存在且有效的应用。通过更新 `enabled: false` 禁用工具；目前没有删除或历史裁剪接口。编辑之后仍保留历史。

`calls.jsonl` 中的 `operation: tools.invoke` 记录包含 `tool_governance`。它不保存资源 ID、检索文本、匹配值、上游 URL/凭证、调用方元数据或原始提供方错误。根据 `tool_id`/`tool_revision` 查询历史并比较 `snapshot_sha256`，可以查看该次调用使用的配置。哈希对哈希字段置空后的公开工具元数据计算，只用于一致性检查，不是签名或防篡改证据库。私有工具凭证快照由实例的 `gateway.key` 加密；备份 `tools.json` 时应保留该密钥。

开始记录中的 `tool_governance.decision` 为 `pending`；进程中断后缺少结束记录表示不完整，不代表已允许。最终写入失败可能留下不完整证据，但不会释放工具输出。授权拒绝也会记录，而且不调用提供方。已有 128 MiB 审计容量和归档流程同样适用。

| HTTP 状态 | 错误代码 | 含义 |
| --- | --- | --- |
| `400` / `413` / `415` | `invalid_tool_request` / `request_too_large` / `unsupported_media_type` | 请求无效或超过输入限制 |
| `401` | `invalid_api_key` | 应用密钥缺失、已轮换或已撤销 |
| `403` | `tool_not_allowed` | 工具或资源访问在执行前被拒绝 |
| `403` | `tool_output_blocked` | 已调用提供方，但命中输出被扣留 |
| `429` | `gateway_busy` | 共享执行槽已满 |
| `502` | `upstream_error`、`upstream_unreachable`、`invalid_upstream_response`、`response_too_large` | 提供方或协议失败，输出被扣留 |
| `503` | `audit_unavailable`、`credential_unavailable` | 必要证据或提供方凭证不可用 |
| `504` | `upstream_timeout` | 超过配置的超时 |

## 边界与验证

调用请求最多 4 KiB，且必须恰好包含一个 `resource_id` 字符串。别名和资源 ID 为 1–100 个 ASCII 字母、数字、点、下划线或连字符，首字符为字母或数字。响应 JSON 外层最多 64 KiB，文本最多 8192 个 UTF-8 字节。提供方超时为 1–30 秒，覆盖本地接纳之后的上游请求和响应读取。模型调用和工具调用共享 64 个并发执行槽。

管理输入最多 16 KiB。私有配置文件最多 4 MiB，支持 32 个工具、所有工具共计 128 个不可变历史版本，每个工具 1–32 个资源，每个资源最多 32 个应用授权。容量耗尽时拒绝修改，不会静默丢弃历史。当前没有自动历史清理、内容留存、流式输出、写入工具执行、MCP 适配器或自动修复。

无需真实模型或外部 API 密钥，就能运行隔离的本地演示：

```bash
make demo-tools
```

命令会构建 `bin/govweave`，启动临时实例和脚本化读取服务，验证六条路径：授权读取、禁止资源、命中输出扣留、调用方伪造身份字段、缺少密钥和已撤销密钥。只有授权读取与输出拦截这两种情况会调用提供方。私有的 `dist/tool-demo/.../summary.json` 保存状态和调用次数，不包含资源 ID、文本或凭证。运行结束后会清理临时实例。构建完成后，运行 `python3 tests/tools-smoke.py` 可以验证演示本身。

从开发者接入到报告留存的完整流程有独立演示：

```bash
make demo-agent
```

它通过 Python 参考客户端执行脚本化的 Agent 工具提议，并分三阶段评估已安装规则包。第一阶段，授权读取、越权拒绝和凭证输出扣留验证执行控制，六项技术控制全部通过。第二阶段，管理员显式切换为 `observe`，放行带匹配凭证的样例，因此阻断配置控制和样本释放控制均失败。第三阶段，管理员恢复 `block`，配置控制重新通过，但先前的观察模式释放记录仍使样本控制失败。脚本会归档并重放每个阶段的报告；重放不新增任何提供方调用。它不使用模型，也不自动修复。私有结果保存到 `dist/agent-demo/.../`；可用 `python3 scripts/demo-agent.py --binary bin/govweave --output-dir <new-directory>` 选择新的输出目录。

测试覆盖配置历史与凭证隐藏、管理认证、允许读取、调用提供方之前拒绝、输出扣留、无效响应与审计故障。本地合成样例验证这些执行路径，不代表通用模型安全准确率或生产可靠性。完整接口见 [OpenAPI](../../api/openapi.yaml) 与 [JSON Schema](../../schemas/tools.schema.json)。

可选的[敏感输出策略](sensitive-output.md)支持在返回前脱敏已识别的所选类别，原有凭证阻断仍优先生效。启用 redact 前应更新 Python 参考客户端：完成的转换会增加版本化证据及 `redact` 决定。

## 可选的检索指令检查

在完整工具创建／更新请求中加入 `"instruction_policy": {"version": "tool-instructions-v1", "mode": "block"}`。`observe` 记录命中并允许其余检查有效的文本，省略或 null 关闭此项检查。PUT 替换配置，需要保留时应一并提交此字段。工具修订号和快照摘要固定每次准入调用的配置，并发修改只影响后续调用。没有该字段的旧快照保持原摘要和行为。

v1 检测器在最多 8192 UTF-8 字节内执行三类固定规则：`task_override`、`authority_spoof`、`role_delimiter`，覆盖明确的中英文任务覆盖语句和部分权限／角色伪装语法，不调用模型。阻断命中返回 `403 tool_instruction_blocked`，文本不会交给 Agent；无法完整检查时返回 `502 tool_instruction_unavailable`，observe 模式也不会放行。资源授权仍先于提供方 I/O，旧凭证阻断优先，返回文本前必须完成终态审计。

`governance.instruction_policy` 含版本、模式、状态、规则 ID、决策、耗时及可选核验证据；既有工具修订号／摘要关联不可变配置。审计不保存命中文本或资源 ID。observe 命中会使总决策为 `observe`；若同时完成敏感输出脱敏，总决策为 `redact`，仍保留指令检查证据。

这是保守的语法控制，不是通用提示注入识别。引用攻击语句的教学材料也会命中；不可信文档不能仅靠自称安全示例绕过检查。间接指令、编码、其他语言和混淆仍存在覆盖缺口。该控制默认不开启，运营方可先测量自己的正常文档再选择阻断模式。[Agent 对照](knowledge-agent.md#新增控制与-v2-对照)保留了漏检和培训文档误拦结果。

## 指令 v2 与精确文档核验

在完整工具配置中选择 `"instruction_policy": {"version": "tool-instructions-v2", "mode": "block"}` 可显式启用新版，v1 继续冻结。v2 保留三类 v1 信号，新增 `answer_manipulation`，识别部分针对助手回答的中英文命令，例如在最终回答中加入某段内容或只返回指定文本。输入仍限 8192 字节、最多四类规则，不调用提供方、不新增外部依赖。这仍是语法检测：正常回答格式要求及引用也可能命中；编码、其他表达和语义意图仍存在缺口。

管理员可为单个资源设置可选 `instruction_review`，包含 `version: exact-instruction-review-v1`、明确的 `detector_version`、完整解码 UTF-8 工具文本的 `content_sha256`，以及一至四个要豁免的 `rule_ids`。核验只适用于该资源及其已授权应用。替换配置时省略或 null 会删除核验；对象必须完整，空对象无效。检测器版本必须等于工具指令策略版本，升级时需明确重新核验或移除旧设置；关闭指令策略时也需移除核验。

从**已人工检查的本机源文档**生成元数据，保留包括末尾换行在内的原始字节：

```bash
python3 scripts/review-tool-document.py --file reviewed-training.txt \
  --detector tool-instructions-v2 --rule task_override
```

辅助命令最多读取 8193 字节，拒绝超过 8192 字节、无效 UTF-8 及非普通文件，只输出核验 JSON。将输出放入目标资源的 `instruction_review`，连同当前全局修订号提交完整工具 PUT。命令不判断安全性、不发送数据、不修改服务器。不要根据刚返回的不可信内容自动生成许可。摘要用于固定管理员许可的文档版本，不证明模型一定会安全地理解文档。

网关放行前比较准入时固定的核验与原始文本字节。内容变化后**不授予规则豁免**，但如果普通检查没有命中，仍可能放行。匹配时也只豁免明确批准的规则，其他命中继续执行原动作；例如 `task_override` 的许可不会豁免新增的 `answer_manipulation`。输入限制、未知结果、资源拒绝、凭证／隐私检查、审计故障仍独立生效。核验既不授予访问权限，也不删除原始命中证据。

`governance.instruction_policy.review` 记录版本、状态（`matched`／`mismatch`／`unavailable`）及 `exempted_rule_ids`。全部命中均获许可时，可以同时出现 `state: observed` 和 `decision: allow`；未被其他控制决定结果时，总原因是 `instruction_review_applied`。部分豁免时剩余命中继续 block／observe。审计不存运行时文档摘要或片段，既有工具修订号与快照摘要关联管理员配置；配置中的文档摘要保存在私有管理历史中。Python 参考客户端校验上述组合，证据矛盾时不会放行。启用 v2 或核验前应更新已复制的参考客户端，旧严格客户端会拒绝新元数据。

[v3 Agent 对照](knowledge-agent.md#v3-指令与文档核验对照)分别测量规则扩展和精确文档许可的作用。既有合规包不会证明通用注入防护能力或管理员核验是否充分。

敏感输出 v3 需在策略中显式选择，工具与模型输出共用：有限配对邮箱格式、单层 Base64 检测、整个编码 token 脱敏，以及 `encoding_limit` 未知结果。启用前更新严格校验的 Python 参考客户端。见 [v3 边界](sensitive-output.md#显式-v3邮箱格式边界与单层-base64)。
