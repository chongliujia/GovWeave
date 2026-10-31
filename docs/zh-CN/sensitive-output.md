# 敏感文本检测与输出保护

[English](../sensitive-output.md) | **简体中文**

版本化敏感文本检测器识别有界的凭证、邮箱地址和中国大陆手机号候选。应用可通过 `POST /v1/content/evaluations` 检查文本；管理员可启用 `sensitive-output` 策略，让非流式模型回答与已配置的只读工具输出使用同一检测器。检测器提供观察结果，服务器保存的策略另行决定哪些类别触发观察、阻断或脱敏。

这是技术内容控制。格式匹配的邮箱或号码不证明其个人归属、保密性或法律违规。`not_observed` 仅表示本版本没有发现其支持的模式，不是通用安全结论。

## 检测范围

| 类别 | 固定规则 ID | 第一版检查范围 |
| --- | --- | --- |
| `credential` | `private_key`、`api_key` | 私钥头及现有的部分凭证样式前缀；不验证凭证是否真实有效 |
| `email` | `email_address` | 实用的 ASCII 邮箱语法子集，检查本地部分、域名长度及标签格式 |
| `phone` | `cn_mobile_phone` | 中国大陆手机号形态；需要显式 `+86` 前缀，或裸号码附近存在电话相关上下文 |

支持的手机号形式可包含空格与连字符，但这不是全球电话号码分类器。编码／混淆披露、不支持的国际号码格式、非 ASCII 邮箱语法、上下文归属及通用语义风险可能漏检。检测器不调用外部模型、NER 服务、网络查询或熵服务，也不生成概率置信度。v2 补齐下述有限格式变体；其余扩展仍需版本化实现与验证。

检测器最多接受 8192 个 UTF-8 字节，最多保留 32 个发现项。每项仅包含类别、固定规则 ID 和原文中右端不包含的字节范围，不包含匹配值。非法 UTF-8、检测输入超限或发现项容量耗尽会得到 `unknown`。发现项超限时标记 `truncated: true`，不会把部分结果当成完整的干净结论。允许空文本，其结果为未发现模式。

## 选择检测器版本

初始策略固定使用 `sensitive-text-v1`。升级程序不会改变现有策略的检测器；保存策略时省略 `detector_version` 会保留当前版本。管理员可显式设置 `"detector_version": "sensitive-text-v2"`，也可通过新策略修订切回 v1。历史快照、独立检测、模型和工具调用记录保留实际版本；执行中的请求不受随后切换影响。应用不能在检测请求中选择或绕过服务器配置的版本。

v2 保留 v1 原样检测，并增加有界的归一化检查：全角 ASCII 字符 U+FF01–U+FF5E、全角空格 U+3000、五种零宽字符 U+200B/U+200C/U+200D/U+2060/U+FEFF，以及邮箱中的 `[at]`、`[dot]`（忽略大小写和相邻空格／制表符）。不拼接换行，不改写普通 at/dot 单词；括号写法仅用于邮箱识别。新增发现使用 `normalized_` 前缀规则 ID，字节范围仍指向原文；观察模式返回原文，不返回归一化文本。多个视图的重叠发现合并，共用 32 项上限，超限继续为 unknown。

这些变换可能把普通文本变成候选，因此应检查业务误报。v2 不提供通用 Unicode 同形字识别、任意密钥语义识别、Base64 解码、国际电话号码或非 ASCII 邮箱识别。

## 通过应用 API 检查文本

将 `GOVWEAVE_ROOT` 设置为网关根地址，不包含 `/v1`；通过应用的秘密管理方式提供 `GOVWEAVE_API_KEY`。没有模型权限的工具专用应用也可使用此接口。管理员会话不能替代应用密钥。

```bash
curl --fail-with-body "$GOVWEAVE_ROOT/v1/content/evaluations" \
  -H "Authorization: Bearer $GOVWEAVE_API_KEY" \
  -H 'Content-Type: application/json' \
  --data '{"text":"联系合成示例用户：alex@example.com。"}'
```

严格 JSON 对象仅接受 `text`，调用方不能提交身份、检测类别或策略决定。JSON 封装最多 64 KiB，解码后的文本最多 8192 个 UTF-8 字节。输入不合法时相应返回 `400`／`413`／`415`。读取请求体后再次验证应用密钥；接口使用共享的有界执行槽位和持久化元数据审计，不调用任何提供方。

成功评估返回 `request_id`、`detection` 和 `policy`。即使策略关闭或应用不在其范围内，`detection` 仍运行所有支持类别；`policy` 记录精确策略版本、所选类别、匹配类别／规则和决定。不会回显输入文本。

**HTTP `200` 仅表示评估完成。** 响应可能包含已观察到的风险、未知检测结果或 `policy.result: block`／`redact`。独立接口不执行后续操作，也不脱敏文本；应用代码须读取结果并控制下一步动作。网关的模型／工具路径会自行执行下述保护。

## 配置输出保护

使用 `GOVWEAVE_COOKIE_JAR` 中已认证的管理员 Cookie 文件。先读取当前策略，再使用其版本保存。该策略默认**关闭**，与模型请求的 `credential-egress` 策略以及读取工具原有的凭证模式彼此独立。

```bash
umask 077
curl --fail-with-body "$GOVWEAVE_ROOT/api/v1/policies/sensitive-output" \
  --cookie "$GOVWEAVE_COOKIE_JAR" > output-policy-current.json
python3 - <<'PY'
import json
current = json.load(open("output-policy-current.json"))
request = {
    "revision": current["revision"],
    "mode": "observe",
    "detector_version": current["detector_version"],  # 显式改为 sensitive-text-v2 可启用新版
    "categories": ["credential", "email", "phone"],
    "application_ids": [],
}
with open("output-policy-update.json", "w") as target:
    json.dump(request, target)
PY
curl --fail-with-body "$GOVWEAVE_ROOT/api/v1/policies/sensitive-output" \
  --cookie "$GOVWEAVE_COOKIE_JAR" \
  -H 'X-GovWeave-Request: console' -H 'Content-Type: application/json' \
  --request PUT --data-binary @output-policy-update.json
```

应用列表为空、缺省或 `null` 均表示所有应用，包括未来新增的应用。非空范围最多允许 64 个已存在的应用 ID。类别从 `credential`、`email`、`phone` 中选择至少一项；策略决定使用所选类别，检测器版本固定。范围、类别和模式来自管理员，不能由模型回答或工具参数指定。

| 模式 | 支持且有效的输出 | 未知或不支持的输出 |
| --- | --- | --- |
| `disabled` | 此策略不执行输出控制 | 保持原有模型／工具行为 |
| `observe` | 返回文本，包括命中所选类别的文本，并记录证据 | 在受保护路径扣留 |
| `block` | 未观察到所选类别命中时返回文本，否则扣留 | 在受保护路径扣留 |
| `redact` | 替换命中的所选内容，复检通过后返回；未命中则原样返回 | 在受保护路径扣留 |

先选择符合应用用途的范围，检查测量误差和实际观察证据，再在可接受误报／漏报权衡的范围内启用阻断。观察模式返回原始文本。需要自动替换命中内容时，显式将 `mode` 设置为 `redact`。

## 脱敏后返回

管理员保存 `"mode": "redact"` 即可启用，应用范围和类别选择仍然生效。策略快照固定保存 `redaction_version: sensitive-redaction-v1`，旧模式不新增此字段。已有的工具凭证阻断仍优先执行，不会被脱敏策略绕过。

处理仅覆盖检测器实际识别到的所选类别：邮箱和手机号按照原文字节位置，用固定的 `[REDACTED]` 替换命中片段；重叠或相邻片段合并，其他文字保持不变。只要命中所选的凭证类别，**整段输出**都替换为 `[REDACTED]`，因为私钥规则可能只定位头部，不能安全地只遮盖头部。v2 的全角、零宽与邮箱混淆形式沿用原文字节映射。

替换后再次运行同一版本检测器。仍有所选类别命中、结果未知、字节范围无效或替换后超过 8192 字节时，返回 `502 content_output_unavailable` 并扣留输出。终态审计失败仍返回 `503`，不会交付处理后的正文。流式输出仍不支持。

实际完成脱敏的模型／工具响应为 HTTP 200，带 `X-GovWeave-Output-Action: redacted`。审计的 `output_policy.result` 为 `redacted`，`state: observed` 描述原始检测结果；`redaction` 仅包含处理版本、`scope`（`matched_spans` 或 `full_output`）、替换片段数及处理与复检耗时。它不保存原文、位置或内容哈希。工具响应另含 `governance.decision: redact`，Python 参考客户端会验证完成证据；未升级的严格客户端可能拒绝新决定。

独立 `POST /v1/content/evaluations` 只返回 `policy.result: redact` 建议，不执行替换、不返回文本或 `redaction` 完成证据。产品事实 `runtime.sample.output_redacted_count` 只统计有完成证据的成功模型／工具调用，排除独立检测、主动测试和失败调用。只脱敏联系人而保留未选中的凭证时，原有凭证释放计数仍保守计入。

脱敏不会提高检测召回率，也不保证匿名化：漏检和未选中的类别仍可能留在输出中。处理后的文本已被改写，应用应读取完成标记，决定如何展示或继续使用。

## 模型与工具执行边界

当模型输出策略启用且应用在范围内时，`stream: true` 会在**上游调用前**返回 `400 content_stream_unsupported`。尚未实现流式内容保护，此行为避免在已启用的保护策略下静默透传未经检查的流。

受保护的非流式 Chat Completions 接受单个完整 `assistant` 文本选项（`finish_reason: stop`），或[知识库 Agent 契约](knowledge-agent.md)规定的、明确声明的单次 `read_resource` 提议。其他工具调用、旧式 `function_call`、文本／动作混合、非文本内容、未完成回答、超过 64 KiB 的封装或超过 8192 UTF-8 字节的文本均以 `502 content_output_unavailable` 扣留。不支持的工具声明在上游 I/O 前返回 `400 content_tools_unsupported`。敏感工具参数在 block 和 redact 模式都直接阻断，不改写成另一个动作；返回提议不代表授予资源执行权限。

成功的受保护响应由网关生成标准化 completion 封装，包含网关请求 ID、配置的模型别名、本地生成时间、已检查文本及支持的数字用量字段。未经检查的提供方扩展、推理字段、提供方 ID 等特有元数据会被丢弃。关闭或不在范围内的流量保持原有[模型适配器行为](model-gateway.md)。

读取工具保留独立的 `credentials-v1` 检查及原有 `block`／`observe` 模式。新策略将评估添加到 `governance.output_policy`，任一控制都可以扣留输出；启用新策略不会放宽资源授权或移除旧凭证控制。使用 Python 参考客户端的集成应采用更新后的示例，它会在向调用方交付文本前校验该可选评估。详见[读取工具接入](tool-governance.md)。

每次获准调用固定其策略快照；后续编辑仅影响之后准入的调用。发送上游前预留审计容量，受保护文本仅在终态元数据决定成功保存后返回。终态记录保存失败时返回 `503 audit_unavailable` 并扣留文本，此时提供方可能已经被调用。

## 历史、证据与限制

| 接口 | 用途 |
| --- | --- |
| `GET /api/v1/policies/sensitive-output` | 当前快照 |
| `PUT /api/v1/policies/sensitive-output` | 检查版本后更新 |
| `GET /api/v1/policies/sensitive-output/history` | 完整有界历史，最新版本在前 |
| `GET /api/v1/policies/sensitive-output/revisions/{revision}` | 精确不可变快照 |
| `POST /v1/content/evaluations` | 应用认证的独立检测 |
| `GET /api/v1/requests` | 管理员查看元数据决定 |

管理写入沿用 JSON、自定义请求头和来源校验。旧版本写入返回 `409 revision_conflict`。私有 `output-policies.json` 最多保存 128 个快照，**包含版本零**，总计最多 2 MiB；采用私有权限和原子写入。容量耗尽返回 `409 output_history_full`，保留当前策略，不会静默淘汰历史。尚无删除／裁剪接口。文件缺失表示初始关闭状态，应将其纳入备份，不要通过删除文件修改保护；无效持久化状态会拒绝启动。

调用记录中的 `output_policy` 仅保存固定的策略／检测器版本、模式、所选与命中类别／规则 ID、状态、原因和检测耗时，不包含输入／输出正文、匹配值、字节范围、内容哈希、原始上游错误或应用／提供方密钥。独立检测响应可向已认证的调用方返回字节范围，但不将这些范围保存在调用记录中。

产品评估的来源快照会保留输出策略版本。策略更新使缓存评估失效；主动测评也会拒绝配置变化，避免发布旧配置结果。旧归档仍可重放，不会凭空生成当时不存在的输出策略证据。证据和重放描述记录时刻的技术观察结果，不是法律合规结论或上线许可。

## 测量与验证

安装[敏感输出技术控制包](sensitive-output-governance.md)草案，可一起评估配置、实际模型／工具执行和历史放行证据。`make demo-output-governance` 使用本机合成服务，验证八项控制、11 份报告，以及策略变化后的历史重放。仅配置当前模式还不够：规则包要求当前修订的实际执行证据，并保留样本中的历史问题。

人工编写的[合成语料](../../tests/testdata/sensitive-validation-v1.json)及其[来源说明](../../tests/testdata/sensitive-v1-provenance.md)覆盖正例、正常近似文本、上下文案例及已知不支持的披露形式。语料编写与检测实现分开，但仍属内部开发基准，不是外部验证或有代表性的客户数据。

```bash
make validate-sensitive
```

命令分别用 v1/v2 测量原 80 条样本与新增 64 条冻结样本，共四份报告。新增样本在实现 v2 前冻结，但由同一开发流程编写，属于内部验证，不是盲测或外部独立验证；见[新样本来源与首次对比](../../tests/testdata/sensitive-v2-provenance.md)。单独测量可用 `go run ./cmd/sensitive-eval -detector sensitive-text-v2 -corpus tests/testdata/sensitive-validation-v2.json`。

命令在 `dist/sensitive-validation/` 下保存新的私有报告。效果只按唯一案例计数，各类别分别报告；未知正例计入漏检，未知负例不会变成真负例。精确率、召回率、未知数和覆盖率分开计算。预热后的本地检测器 P50／P95／P99 不含 HTTP、提供方／模型、排队或审计 I/O，不能视为端到端服务延迟保证。

网关测试覆盖独立检测、应用身份、范围／类别、输出扣留、未知／不支持输入、调用前拒绝流式请求、调用内快照及审计故障。接口契约见 [OpenAPI](../../api/openapi.yaml) 和[内容 Schema](../../schemas/content.schema.json)。

运行 `make demo-sensitive` 依次验证 v1 原始样式和 v2 混淆样式，可用隔离的本机脚本模型体验真实 HTTP 流程：独立检测、三类输出拦截、观察模式返回、脱敏与无命中放行，以及访问上游前拒绝流式请求，无需模型账号。先 `make build`，再显式执行 `python3 scripts/demo-sensitive.py --kimi` 才会调用 `https://api.moonshot.cn/v1` 的 `kimi-k2.6`：密钥通过隐藏输入或 `MOONSHOT_API_KEY` 获取，最多三次合成请求，每次最多生成 128 tokens，不重试；完成后删除临时加密网关配置，仅在 `dist/sensitive-demo/` 保留私有结果元数据。非思考模式采用[官方 K2.6 参数](https://platform.kimi.com/docs/guide/kimi-k2-6-quickstart)。模型未按预期输出时报告 inconclusive，不改成成功；这几个请求仅验证接入链路。

编译后运行 `python3 tests/redaction-smoke.py`，可用真实 Python 参考客户端验证联系人脱敏、整段凭证替换、原有阻断优先、未知结果扣留、审计隐私与临时配置清理；只访问本机合成服务。

## 精确公开邮箱许可

敏感输出管理策略支持可选 `public_emails`：管理员登记的最多 16 个唯一、完整 ASCII 邮箱地址。其作用范围沿用 `application_ids`（空表示所有应用），适用于模型最终文本、读取工具返回及独立评估建议。PUT 省略／null／空数组会清空列表。历史快照及调用准入时固定的策略修订保留各自许可；应用和模型／工具文本不能声明许可。

例如 `"public_emails": ["support@example.com"]` 只许可该字面地址，其余邮箱仍执行所选动作。比较区分大小写，不接受规范化／混淆写法、通配符或整个域名许可，不豁免凭证、行动参数和未完整检测的输出。公开与私密邮箱混合时保留公开地址、脱敏私密地址；命中所选凭证类别仍替换整个输出。转换后按相同已固定许可复检。

原始检测结果保持不变，包括 `state: observed`；公开邮箱许可表示允许披露，不表示原检测出错。策略 `matched_categories`／`matched_rules` 描述应用许可后仍需处理的发现。可选 `public_email_exceptions` 只记录豁免数量，调用审计不记录邮箱值。资源标为 public 本身既不授予访问，也不生成内容许可。管理员应仅登记确实允许公开的地址。

## 显式 v3：邮箱格式边界与单层 Base64

管理员在新策略修订中设置 `detector_version: sensitive-text-v3` 才会启用。已有策略及冻结的 v1／v2 源码保持原行为；省略版本字段会保留当前选择。内容检查、模型回答和读取工具输出共用所选版本。启用前需更新已复制的 Python 参考客户端，旧严格客户端会拒绝不认识的证据。

v3 识别配对反引号、`**` 或 `__` 中的完整 ASCII 邮箱，并要求外围满足有限的标点／空白边界；`formatted_email_address` 的范围只包含地址，不包含格式符号。本机复现了 v2 将开头 Markdown 符号算入邮箱候选、从而使精确公开邮箱许可失效的问题。这只是小范围格式识别，不是完整 Markdown 解析。只有管理员明确列出的、区分大小写的精确地址才能获许可；其他域名、变形写法、凭证、歧义格式及不完整检查不会因此获许可。历史真实回答没有保留，所以本机复现不能确认那次回答的具体格式。

v3 还检查独立连续、规范形式的 Base64／Base64url token，支持有／无填充，最短八个字节。单个编码 token 最多 2,048 字节，最多检查 32 个解码后的 UTF-8 文本视图。二进制或含控制字符的载荷不当作文本处理，但允许制表符和换行／回车。只解码一层，再应用有界的原文／归一化与格式规则。发现项使用 `base64_` 前缀，范围指向**原始编码 token 全部字节**，因此脱敏会替换整个编码片段；编码凭证仍会触发整段输出替换。解码正文不返回、不持久化，编码后的公开邮箱也不能使用公开许可。

疑似编码的 token 超长或解码视图预算耗尽，会得到 `unknown`、`encoding_limit`、`truncated: true`，不允许部分检查后放行。原有 8,192 字节输入和 32 项发现上限仍生效，因此较长的普通不透明字符串也可能变成未知。嵌套编码、十六进制、拆行 token、任意变换和通用语义隐私仍不支持。两个历史验证集各增加了一条有效负例的未知结果，这个取舍保留在报告中。

[45 条内部语料](../../tests/testdata/sensitive-validation-v3.json)、[语料冻结记录](../../tests/testdata/sensitive-v3-freeze.json)和[源码冻结记录](../../tests/testdata/sensitive-v3-source-freeze.json)保留了验证顺序。语料在观察 v2 真实失败后、实现 v3 前编写，开发者可见，不是盲测。一条输入超限样例不进入质量分母；两条编码预算超限样例仍计入分母。

| 新语料上的检测器 | 凭证 TP／FP／FN | 邮箱 TP／FP／FN | 手机号 TP／FP／FN | 有效样例中结果确定 |
| --- | --- | --- | --- | --- |
| v2 | 0 / 0 / 2 | 12 / 0 / 15 | 0 / 0 / 4 | 44/44 |
| v3 | 2 / 0 / 0 | 23 / 0 / 4 | 4 / 0 / 0 | 42/44 |

未知正例计入漏检，未知负例不计作正确放行。四条邮箱漏检包括不支持的形式及超长编码输入。本机该语料的 v3 检测器 P95 约 60.9 微秒，v2 约 15.4 微秒，各测时 4,500 次；不含 HTTP、模型推理、审计和策略处理，不能作为生产 SLA。小规模内部语料没有观察到误报，不能由此推断总体精确率。

```bash
make validate-sensitive-v3
python3 scripts/accept-knowledge-agent.py --controls instructions-v2-reviewed \
  --sensitive-detector sensitive-text-v3
```

验收语料和评分规则未改变，验收入口默认仍使用 v2。报告保留 `sensitive_detector_version`、检测器源码及对应策略审计。本机／真实结果分开保存在 [Agent 评估说明](knowledge-agent.md)中。
