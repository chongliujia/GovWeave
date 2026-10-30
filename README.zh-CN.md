# GovWeave

[English](README.md) | **简体中文**

面向 AI 应用开发者与 Agent 平台开发者的开源、自部署 AI 治理网关。通过统一入口调用模型，按应用执行运行时控制，并为技术层面的安全与合规评估留存证据。

部署在自己的基础设施上，配置 OpenAI 兼容模型接口，为每个应用分配密钥和模型权限。应用使用网关地址与管理员配置的模型别名接入，无需注册 GovWeave 云端账号。

**当前为 0.2.0-dev 预览版**，采用单进程、单组织部署，尚不是完整的 GRC 平台或法律合规认证服务。

接入自己的应用请从[应用接入指南](docs/zh-CN/application-onboarding.md)开始：启动网关、配置模型、创建应用密钥，再复制 BASE URL 和模型别名。“部署与接入”页面支持选择模型、生成非流式 Python/cURL 示例、仅检查本机配置，以及显式发送一次测试请求并核对审计记录。

[风险证据](docs/zh-CN/risk-evidence.md)将调用、采集内容、策略快照和检测发现关联起来。按应用显式启用的加密留存支持 JSON 响应及有界 SSE 帧证据，提供内容访问审计和应用范围内的关系图。普通调用日志仍只存元数据；归档产品报告保存运行统计对应的具体样本记录。

## 当前可以做什么

- 无云端账号注册，首次设置管理员密码即可使用；本地控制台与静态资源随 Go 二进制分发。
- 控制台默认英文，支持即时切换简体中文并记住语言偏好；所有语言资源随程序离线提供。
- 企业配置自己的访问地址，自动生成模型 BASE URL 和实际接入示例。
- 配置 OpenAI 兼容的模型连接、上游凭证、企业模型别名、启用状态和超时。
- 创建应用、授予模型权限、生成一次性展示的 API Key，并轮换或撤销。
- 提供 `POST /v1/chat/completions`（普通 JSON / SSE）和 `GET /v1/models`。
- 提供[只读工具治理 API](docs/zh-CN/tool-governance.md)：执行前校验应用与资源授权、返回前检查凭证样式，保留配置历史和决策依据，提供 Python 执行器参考示例，并将工具证据纳入产品持续评估；可创建没有模型权限的工具专用应用。
- 提供[敏感文本检测与输出保护](docs/zh-CN/sensitive-output.md)：独立应用检测 API，以及按应用启用的非流式模型回答／工具输出观察、阻断与复检后脱敏返回，共用有界的凭证、邮箱与中国大陆手机号检测器；可显式选择 v2/v3 的有限格式归一化与编码检测，保留旧版本及冻结测量。
- 运行时策略中心可按应用和模型范围检查请求中的私钥标记及部分 API 密钥样式；默认关闭，支持观察与阻断。每次保存保留不可变快照，可按调用记录中的版本追溯配置。
- 通用合规评估引擎可加载本地 JSON 规则包，通过管理 API 判断技术控制项是否满足；登记产品后可自动采集网关配置和有界调用样本并重评，不附带已审核法规包。见[规则包与评估](docs/zh-CN/compliance-engine.md)。
- 提供[欧盟 AI 客服透明度草案](docs/zh-CN/eu-transparency-reports.md)，区分控制缺口、证据缺口和人工复核；可显式保存独立报告快照及历史重放，数值运行事实引用实际参与计数的样本请求。
- 提供[已知合成标记检测与效果测量](docs/zh-CN/canary-validation.md)，支持有限编码识别，并保留冻结样本中的误报、漏报和未知结果；可用[效果与成本回测](docs/zh-CN/canary-benchmark.md)比较检测阶段的增益与本机耗时，或用[检测器插件与分流回放](docs/zh-CN/detector-routing.md)验证快慢路径；真实模型效果尚未验证。
- 提供[主动测评](docs/zh-CN/active-assessments.md)：版本化测试包、部署前测试、显式开启的运行期复测和部分 NIST 生命周期证据；可明确开启独立私有测试回答留存。
- 调用记录保存应用、模型别名、请求 ID、授权决定、执行结果、耗时和配置版本，不保存提示词、回答或凭证。
- 提供[风险证据留存](docs/zh-CN/risk-evidence.md)：按应用显式启用，独立加密保存原始与准备交付的内容，关联策略快照、检测器版本与发现；管理员查看正文会留下访问审计。
- 提供 [SSE 流式证据](docs/zh-CN/risk-evidence.md#流式响应证据)：区分已验证上游帧与客户端写入尝试，记录帧时间线、带密钥指纹、结束／中断状态及留存缺口。
- 提供[异构多 Agent 追踪](docs/zh-CN/agent-tracing.md)：显式关联模型、工具和内容检测调用，支持并行分支、汇合与重试；应用只能查询自身记录，管理员可明确选择应用后聚合查看。
- 上游凭证使用 AES-256-GCM 加密保存；应用密钥只持久化 SHA-256 哈希与识别前缀。

**广泛语义风险识别、流式输出阻断、MCP 执行、审批、全面且经过审核的 EU/US 法规覆盖、完整企业 IAM 和 HA 尚未实现。** 当前的 allow/deny 表示对应技术策略决定，不代表法律合规结论。未支持的模型和 MCP 接口返回 `501`。

## 启动与第一次调用

源码开发需要 Go 1.24+；分发构建请使用受支持且包含安全更新的 Go 版本（Docker 固定 1.26.9）。服务无第三方 Go 模块和前端构建依赖。

```bash
go run ./cmd/govweave -config examples/deployment.json
```

也可以在安装 Docker 和 Compose 后运行：

```bash
docker compose build
docker compose up -d --no-build
```

从仓库根目录执行以上命令，两种启动方式选择一种即可。默认访问地址都是 `http://127.0.0.1:8080`；源码启动的数据位于 `./data`，Compose 使用独立的命名卷。远程访问、HTTPS 和持久化配置见[部署指南](docs/zh-CN/deployment.md)。

1. 打开 `http://127.0.0.1:8080`，首次设置并确认管理员密码（12–128 个字符），即可进入控制台；以后使用该密码登录。请先完成此步骤，再开放给其他用户访问。
2. 在“部署与接入”填写组织和实际根访问地址，保存配置。
3. 在“模型连接”填写上游 BASE URL、真实模型 ID、凭证和企业别名（例如 `internal-assistant`）。本地无鉴权模型可不填凭证；HTTP 上游需要明确勾选允许。
4. 在“应用与密钥”创建应用，勾选允许使用的模型，保存只展示一次的应用密钥。
5. 回到“部署与接入”，选择该应用并复制示例。将应用密钥设置为调用程序的 `GOVWEAVE_API_KEY`，再执行示例。
6. 可选：在“运行时策略 / Runtime policies”配置凭证检测，先观察命中，再按需启用阻断。观察模式仍转发原始请求及其中凭证。
7. 在“调用记录”刷新查看结果。连接检查仅调用上游 `GET /models`，实际推理须通过应用调用验证。

离线二进制包解压后用 `./govweave -config examples/deployment.json` 启动。网关可离线安装；推理需要可达的企业本地模型或已配置的外部服务。选择外部服务时，请求内容会发送给该上游。

详见[文档目录](docs/zh-CN/README.md)、[部署与配置](docs/zh-CN/deployment.md)、[模型接入](docs/zh-CN/model-gateway.md)和[运行时策略](docs/zh-CN/runtime-policies.md)。

## 地址与请求示例

`GOVWEAVE_BASE_URL` 和 `GOVWEAVE_API_KEY` 是调用程序使用的环境变量，不是服务端配置项。前者填实际网关地址加 `/v1`（例如 `http://127.0.0.1:8080/v1`），后者填应用密钥，不填管理员密码或上游凭证。以下别名必须先创建并授权：

```bash
curl --fail-with-body "${GOVWEAVE_BASE_URL%/}/chat/completions" \
  -H "Authorization: Bearer $GOVWEAVE_API_KEY" \
  -H "Content-Type: application/json" \
  --data '{"model":"internal-assistant","messages":[{"role":"user","content":"总结这份资料。"}],"stream":false}'
```

Python SDK 示例、流式调用及工具执行边界见[模型与应用接入指南](docs/zh-CN/model-gateway.md)。

## 查看风险证据

采集默认**关闭**。在控制台打开“风险证据”，展开留存设置，明确选择应用，并选择“仅元数据”或“完整采集”。现有应用调用无需增加采集参数；新建应用不会自动加入范围。

1. 通过网关发送获准请求，按应用或请求 ID 查找记录。
2. 检查原始输入、准备发送的上游请求、观测到的上游输出和准备交付的应用输出。可用阶段取决于调用执行到了哪里；被阻断或脱敏的原始输出与准备返回的内容分别保存。
3. 查看检测发现、检测器／策略版本及留存关系图。管理员可先查看内容预览，再显式查看原文；每次正文访问均先记录审计，再释放内容。
4. 对 SSE 展开帧时间线，查看偏移量、大小、观测时间和结束原因。`stream_incomplete` 将未完成的流与实际写入／刷新失败区分开。

默认保留 **30 天、每对象 64 KiB**，可配置为 1–365 天及 4 KiB–1 MiB。正文超过上限时全部省略，保留计数和带密钥指纹。流式时间线最多保存前 **128 帧**，并显式标注截断。SSE 证据覆盖已验证帧与写入尝试，不包含无效帧／错误帧正文，也不能证明客户端已收到。证据在终态审计提交后保存；进程崩溃可能丢失仍在进行中的流式证据。

**SSE 证据留存不会开启流式安全拦截。** 适用的输出保护策略仍会在访问上游前拒绝 SSE。证据图覆盖所选应用中已留存的调用，调用方声明的 Agent 关系不代表已验证的因果关系。产品报告样本独立于正文采集保留，不代表已覆盖整个产品。完整限制、缺失状态及恢复方式见[风险证据指南](docs/zh-CN/risk-evidence.md)。

## 请求保护与数据处理

在“运行时策略”配置内置凭证外发策略。策略默认关闭；“观察”会记录命中的规则 ID 并转发原始请求，其中可能包含凭证；“阻断”会在访问模型提供方前拒绝命中请求。应用与模型范围必须同时匹配。

检测在本机运行。普通审计日志不保存提示词、回答、命中的秘密或原始上游错误；显式启用的完整证据采集可以将敏感请求／响应正文保存到独立的 AES-256-GCM 证据库，不会复制到普通日志、图谱或报告。配置与记录保存在数据目录中；获准请求会发送给配置的模型提供方。自部署网关不意味着云端模型变成本地模型。

上游凭证使用本机密钥加密，应用密钥保存为哈希与识别前缀。当前记录存储不具备完整防篡改保证，证据密文认证也不构成完整取证链或外部存证。停机后应整体备份私有数据目录，包括配套的 `evidence.key` 和 `evidence/`，详见[存储与恢复](docs/zh-CN/risk-evidence.md#存储到期与恢复)。

规则命中或未命中都不构成法律合规结论。[通用评估器](docs/zh-CN/compliance-engine.md)接受本地规则包；附带的[欧盟交互透明度映射](docs/zh-CN/eu-transparency-reports.md)为未经专家审核的有限草案。[登记产品](docs/zh-CN/product-assessments.md)可以跟踪网关配置和有界调用样本，尚不采集经独立验证的产品全量证据。

## 示例与本机试用

运行 `make demo-support-agent`，可试用通过网关接入的独立文件知识库客服应用。九个本机场景保留已知十六进制漏检，并测量本机读取路径增量；另有三例 Kimi 实测，见[开发者试用指南](docs/zh-CN/support-agent-trial.md)。

运行 `make demo-multi-agent-trace`，可查看使用独立应用密钥的 Python/Node 并行协作、汇合和被拒绝的重试。本机示例检查五次网关调用及查询隔离，无需模型账号。追踪仅反映已观察调用和调用方声明的关系，不判定任务完成，见[异构 Agent 追踪指南](docs/zh-CN/agent-tracing.md)。

可选的[真实框架追踪联调](docs/zh-CN/framework-tracing-trial.md)使用固定版本 LangGraph 和 Pydantic AI，通过序列化异步消息交接任务，验证并发隔离、超时、显式重试、取消和未知引用。模型决策采用本机固定脚本以复现故障；框架依赖装在独立 Python 环境，不改变网关运行依赖。

运行 `make demo-sensitive` 可体验本地模型输出拦截，`make validate-sensitive` 可测量冻结样本。显式运行 `python3 scripts/demo-sensitive.py --kimi` 会隐藏输入密钥，并向 Moonshot 国内接口发送三次合成测试请求。见[敏感输出指南](docs/zh-CN/sensitive-output.md)。

运行 `make demo-output-governance`，可将模型／工具输出保护接入八项技术控制、自动评估及 11 份报告快照，验证恢复保护后仍保留先前证据缺口。全程使用本机合成服务，见[敏感输出规则包](docs/zh-CN/sensitive-output-governance.md)。

运行 `make demo-output-assessment`，可主动验证三类敏感输出与正常对照，将当前部署前／运行期结果关联到产品报告。见[主动输出控制测评](docs/zh-CN/output-control-assessments.md)。

运行 `make demo-tool-assessment`，可验证读取工具的敏感输出保护、越权拒绝及当前产品证据。见[主动读取工具测评](docs/zh-CN/tool-control-assessments.md)。

运行 `make demo-application-assessment`，可将独立模型与工具测试合入同一份产品报告，见[同一产品的模型与工具测评](docs/zh-CN/application-assessments.md)。

运行 `make evaluate-agent`，可对模型 → 读取工具 → 回答的完整有界流程执行固定正常／攻击案例，并保存不含正文的任务报告。默认模式使用本机脚本模型；另一次有界 Moonshot K2.6 实测在 v2 加文档核验配置下执行了七个案例，攻击控制通过 3/4，正常任务完成 2/3。真实入口需显式开启，已知失败保留在文档中。见[知识库 Agent 行动链测评](docs/zh-CN/knowledge-agent.md)。

运行 `make evaluate-agent-controls` 可比较可选工具指令检查与精确公开邮箱许可；报告同时保留间接／编码攻击漏检及引用攻击的培训材料误拦。

运行 `make evaluate-agent-reviews`，可分开比较指令 v1、v2 和精确资源文档核验；核验许可用于保留指定版本的培训材料，不授予访问权限，也不豁免其他输出控制。

运行 `make accept-agent` 可执行三组配置的有界本机验收，保留完整计划分母、网关作用审计证据，并提供显式开启的 Moonshot 预检入口。执行完成不代表控制全部通过，编码泄露仍是已测得的漏检。见[验收指南](docs/zh-CN/knowledge-agent.md#三组配置的有界验收)。

显式选择 `sensitive-text-v3` 可启用有限配对邮箱格式和单层 Base64 检测。`make validate-sensitive-v3` 保留不支持形式的漏检及编码上限未知结果；[v3 指南](docs/zh-CN/sensitive-output.md#显式-v3邮箱格式边界与单层-base64)说明范围和实测取舍。

运行 `make demo-agent`，可通过 Python 执行器示例体验工具调用、规则包持续评估和报告重放；调用提议与读取服务均由脚本提供，无需模型账号。`make demo-tools` 另验证原始 API 的授权读取、执行前拒绝与输出拦截。见[工具接入指南](docs/zh-CN/tool-governance.md)。

还没有模型或测试应用？运行 `make demo`，可启动隔离的本机模拟客服，查看“正常 → 故意出错 → 修复”的测评过程。需要 Python 3，无需提供者账号，详见[本机演示](docs/zh-CN/local-demonstration.md)。

## 开发验证

```bash
make test
make check
make build
make package
```

`make test` 使用 race detector，需要 C 编译器和本机临时端口权限；测试仅连接本地模拟服务。`make check` 需要 Node 检查脚本语法；构建和运行无需 Node。浏览器、真实 SDK 和容器验收见 [开发与验收](docs/zh-CN/development.md)。

执行 `make build` 后，按[开发文档](docs/zh-CN/development.md)配置 Playwright 和 Chrome，运行 `node tests/evidence-smoke.cjs`，可验证采集、阻断前原始输出、特权内容访问、报告重放、正常／中断 SSE、留存上限与重启恢复。测试使用隔离的本机合成服务，无需模型 API Key。

默认英文文档位于 `README.md` 和 `docs/`，中文版本位于本文件和 `docs/zh-CN/`。示例与能力说明应和代码、API 契约保持一致。

## 设计与接口

- [ADR 0001：自部署网关入口](docs/zh-CN/adr/0001-gateway-first.md)
- [ADR 0002：模型访问与调用记录](docs/zh-CN/adr/0002-model-gateway.md)
- [ADR 0003：管理员密码与浏览器会话](docs/zh-CN/adr/0003-password-login.md)
- [ADR 0004：请求凭证策略](docs/zh-CN/adr/0004-request-credential-policy.md)
- [ADR 0010：按应用留存风险证据](docs/zh-CN/adr/0010-scoped-risk-evidence.md)
- [风险证据、SSE 留存与内容访问审计](docs/zh-CN/risk-evidence.md)
- [异构 Agent 追踪与关联边界](docs/zh-CN/agent-tracing.md)
- [产品评估与报告证据](docs/zh-CN/product-assessments.md)
- [部署 Schema](schemas/deployment.schema.json)、[实例更新 Schema](schemas/instance.schema.json)、[连接与应用 Schema](schemas/gateway.schema.json)、[策略状态 Schema](schemas/policies.schema.json)
- [OpenAPI 契约](api/openapi.yaml)

[早期草案](docs/zh-CN/archive/initial-design.md)已归档，其“Eval 优先、已有 GRC”前提已更新。当前 `agent.md` 是英文贡献者指南，以当前文档及 ADR 为准。后续继续建设 MCP 工具执行边界和经过人工审核的 EU/US 法规控制映射。

采用 [Apache-2.0](LICENSE)；分发依赖许可见 [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES)。
