# 开发与验收

[English](../development.md) | **简体中文**

服务仅使用 Go 标准库，源码编译最低需要 Go 1.24（使用标准库 `crypto/pbkdf2`），验收和分发固定 Go 1.26.9。控制台界面是嵌入式静态资源，修改后需要重新构建/启动 Go 服务。

```bash
make test
make check
make build
make package
```

- Go 测试覆盖 URL/名称校验、文件和环境变量优先级、部署字段锁定、重启恢复、文件权限、并发保存冲突、文件损坏拒绝启动、进程锁、密码哈希与权限、重复初始化拒绝、登录限速、会话过期与退出撤销、旧实例迁移、管理员认证、Origin/CSRF 校验、请求体限制和真实能力状态。
- `go test -race ./...` 需要可用的 C 编译器。所有 Go 测试无外部服务依赖；网关集成测试会监听本机临时端口。
- `go vet`、gofmt 和 JavaScript 语法检查由 `make check` 执行。
- `docker compose config --quiet` 检查 Compose 语法。完整容器验收还需构建镜像并启动，不能仅用语法通过代替部署通过。

构建镜像后，可以执行 `python tests/container-smoke.py`。它创建独立临时 Compose 项目，验证认证、重启持久化、非 root/只读运行，以及 `--network none` 下启动；结束时删除该测试项目和测试卷。需要本机 Docker 权限和 Python 标准库，不读取真实实例数据。

## 浏览器流程测试（可选开发依赖）

`tests/browser-smoke.cjs` 使用 Playwright 和独立的无头 Chrome，不访问个人浏览器资料。不属于产品依赖，不进入镜像或离线包。

在开发环境提供 Playwright（本次验证使用 1.62.1）以及 Chrome，确保 Node 能解析 `require('playwright')`。例如将开发依赖安装在独立目录，并通过 `NODE_PATH` 指向该目录的 `node_modules`。默认 Chrome 路径是 `/usr/bin/google-chrome`，可通过 `GOVWEAVE_BROWSER_PATH` 覆盖。

```bash
make build
node tests/browser-smoke.cjs
```

测试在 `127.0.0.1:18081` 启动自己的临时实例；端口占用时可设置 `GOVWEAVE_TEST_PORT`。验证首次设置密码、确认密码、错误密码、登录、刷新保留会话、非法地址、初始化、并发页面冲突、配置导出、桌面/移动布局、真实进程重启和退出，以及模型配置、连接检查、应用授权、密钥轮换／撤销、实际调用和记录查询。检查浏览器密码不进入 localStorage/sessionStorage、会话 Cookie 的 HttpOnly/SameSite 属性、无外部页面请求、无页面 JavaScript 错误。

测试结束会关闭浏览器与服务，删除临时凭证和数据。截图保存在已被 Git 忽略的 `dist/browser-smoke/` 中，使用合成组织名称，不含真实凭证。

使用相同浏览器依赖执行 `node tests/onboarding-smoke.cjs`，可验证应用接入流程。测试在动态 loopback 端口启动独立网关和合成模型服务，覆盖模型选择、非流式示例、不调用提供方的配置检查、应用密钥身份、单次调用及对应审计记录、异常响应、证据缺失、输出阻断、取消、密钥清理和双语移动布局。报告和截图保存到 `dist/onboarding-smoke/` 下新建的私有目录。本测试不验证 Docker 或真实模型提供方。

`node tests/evidence-smoke.cjs` 使用相同的开发专用浏览器依赖和动态回环端口，验证显式启用采集、阻断前原始输出、带访问记录的脱敏／原文复核、应用隔离、写入保护、准备返回的输出、调用方声明的追踪关系、重启恢复与存储隐私。还检查正常结束和提前断开的 SSE、正文与帧清单上限、元数据模式及双语流式时间线。任务证据测试覆盖明确选择多个应用、缺失证据、进入单份证据，以及范围切换后的迟到响应。快照测试覆盖视图变化后拒绝保存、重启后按精确范围读取历史、JSON 字节校验值、Markdown 下载和迟到响应不能恢复下载链接。Go 测试另覆盖正文到期、文件篡改、错误密钥、不安全权限与归档容量。元数据测试报告与截图写入 `dist/evidence-smoke/` 下的新目录；结束后删除测试用合成正文保险库。不调用真实提供方，不验证 Docker 部署。采集和完整性边界见[风险证据](risk-evidence.md)。

`go test -run '^$' -bench '^BenchmarkEvidenceCapture$' -benchtime=20x -benchmem ./internal/gateway` 单独测量本机证据库的关闭、元数据和完整模式，每次捕获四个 8 KiB 或接近 1 MiB 的对象。固定 20 次避免把容量耗尽当成性能测量；启用模式包含 HMAC、序列化、加密和同步落盘。这些串行平均值不含模型、普通审计、检测器和网络，不是 P95/P99 或端到端 SLA。完整留存会增加存储时延和内存分配。

`go test -run '^$' -bench '^BenchmarkEvidenceStreamFrames$' -benchtime=100x -count=3 -benchmem ./internal/gateway` 另行比较关闭、仅元数据和完整采集下的 SSE 处理。每次处理 32 或 1,024 个 1 KiB 帧及结束标记，正文上限固定 64 KiB。计时包含帧解析、清单、增量 HMAC 和有界内存留存，不含网络、模型、策略检查、普通审计及最终证据落盘。这些串行 CPU／分配样本不测量首 token 延迟或生产并发吞吐量。

## 只读工具验收

`python3 tests/tool-client-test.py` 在不建立网络连接的情况下检查 Python 标准库参考客户端：后端身份绑定、参数校验、输出证据一致性、响应上限、拒绝重定向与错误脱敏。`make demo-agent` 通过真实网关与脚本化服务运行该客户端，并评估、归档三个规则包阶段；`python3 tests/agent-smoke.py` 验证历史发现保留及无提供方调用的重放。Python 仅用于示例和测试，网关运行不依赖 Python。

`make demo-tools` 编译网关并通过真实 HTTP 接口调用本地只读服务；`python3 tests/tools-smoke.py` 另验证模拟服务协议。无需模型 API Key。Go 测试覆盖执行前授权、读取请求期间的密钥变更、输出阻断／观察、调用内快照、无效及超限输出、超时，以及准入前和释放输出前的审计失败。见[只读工具治理](tool-governance.md)。

## 合成标记效果测量

`make validate-canary` 离线测量冻结标注样本；退出成功表示测量完成，不代表零漏检。编译后用 `python3 tests/canary-smoke.py` 单独验收真实二进制的随机标记注入及编码泄露识别，见[标记检测与验证](canary-validation.md)。

`make benchmark-canary` 使用单／双工作器，分别测量两个语料集上的精确匹配、规范化、单层和两层阶段。效果按唯一样本统计一次；重复回放记录本机调用 P50／P95／P99，并另存新的私有报告。参数、测量边界及解读见[效果与成本回测](canary-benchmark.md)。

## 主动测评验收

`make demo` 提供可反复运行的本机模拟客服，并导出实际合成测评结果；`python3 tests/demo-smoke.py` 验证一键／交互流程与模拟接口输入边界。详见[本机演示](local-demonstration.md)。

`make build` 后执行 `python3 tests/active-smoke.py`，验收真实二进制、本机模拟上游、部署前及运行期测试、失败变化、重启后的周期执行、私有留存及无模型调用的重放。`--output-dir dist/active-demo/new-run` 可保留合成结果。Go race 测试还覆盖授权、版本关联、未知、容量及损坏处理，见[主动测评](active-assessments.md)。

## 当前支持范围

Linux 构建和运行路径已作为主要目标；macOS 的文件锁和打包分支尚需平台 CI 验证，Windows 不支持当前文件锁实现。模块语言版本是 1.24，生产分发应使用受支持的安全更新工具链，Docker 构建固定 Go 1.26.9。

MCP、全面且经过审核的法规覆盖、生产性能与 HA 尚未验收；真实云厂商兼容性尚未验证，不能依据本地模拟测试宣称全面兼容。

## 模型网关验收

Go 测试还覆盖：上游凭证加密与应用密钥哈希、授权更改、停用连接、保存失败保持旧状态、开始事件恢复、记录容量预留、记录写入失败停止上游调用、重定向拒绝、错误脱敏、输入／输出上限、流式逐事件送达、提前 EOF、错误事件、取消传递、超时和有限并发。

使用已安装的 OpenAI Python SDK 和 httpx 可运行真实 SDK 的本地协议测试：

```bash
make build
python3 tests/sdk-smoke.py
```

脚本创建自己的临时网关与模拟上游，验证 models.list、普通响应、SSE、权限拒绝、撤销和记录隐私。不使用真实 API Key，不产生模型费用，不访问云端。当前验证 SDK 版本为 1.53.0；其他版本应另跑兼容测试。SDK、httpx、Playwright 都只是开发测试依赖，不进入产品运行时。

容器构建包含系统 CA 文件及其许可，用于校验 HTTPS 上游；内网私有 CA 仍由部署环境提供。

## 控制台视觉与交互

控制台采用浅色、紧凑布局：单一导航、运行总览、模型与应用列表、右侧编辑面板、调用详情。总览统计来自当前配置和最近 100 条调用记录，不是历史全量或按日统计；拓扑表示配置关系，不代表已经探测到网络连通。空实例显示实际空状态，没有填入演示指标。

浏览器验收同时检查总览计数、列表搜索、编辑时不回显凭证、面板内错误提示、Escape 关闭、调用详情不显示正文，以及移动端无横向页面溢出。截图关闭动画以便复核。可用 `GOVWEAVE_TEST_BINARY=bin/govweave-preview` 指定候选二进制，避免测试期间替换当前运行服务。界面仍无远程字体、CDN 或新的运行依赖。

## 语言与文案

`internal/server/web/i18n.js` 使用英文消息 ID 和集中中文词条，默认 `en`，支持 `zh-CN`。HTML 的 `data-i18n-parts` 标记静态文本节点，`data-i18n-placeholder` / `title` / `aria-label` 标记属性；仅这些明确标记的产品文案会翻译。动态文案使用 `t(message, values)`，变量保持原样并通过 `textContent` 输出，不使用 HTML 插值。语言切换重新渲染标签和已加载数据，不重新请求配置或重置表单。

新增或修改文案时同步维护词条和默认英文 HTML。`node tests/i18n-check.cjs`（也包含在 `make check`）检查动态词条覆盖、英文默认页面、参数保留和本地存储不可用时的回退。浏览器测试以中文浏览器环境验证英文默认，覆盖中英文切换、刷新持久化、登录/编辑草稿保留、一次性密钥保留、授权选择、服务器错误翻译及两种语言下的手机布局。

## 请求凭证策略验收

`internal/gateway/policy_test.go` 覆盖默认关闭、观察/阻断、应用与模型范围交集、JSON 转义、重复字段、工具参数、规则选择、普通/流式阻断时零上游请求、无匹配流式透传、记录隐私、版本冲突、并发快照、保存失败和损坏文件。HTTP 测试覆盖策略管理认证、同源请求、严格 JSON 和版本冲突。浏览器流程覆盖中英文策略配置、范围选择、观察转发、阻断、记录详情和重启恢复。

可单独测量本地检测成本（不含磁盘同步、网络或模型推理）：

```bash
go test ./internal/gateway -run '^$' -bench BenchmarkCredentialPolicy -benchmem
```

这只是本机合成请求微基准，不代表生产吞吐或端到端延迟 SLA。

## 文档规范与源码布局

默认英文入口为 `README.md` 和未加语言后缀的 `docs/*.md`。中文入口为 `README.zh-CN.md` 和 `docs/zh-CN/`。每篇维护中的指南提供语言切换链接；修改命令、功能、存储或边界时同步两种版本。旧方案保存在[归档](archive/initial-design.md)，不作为当前研发路线。

| 路径 | 职责 |
| --- | --- |
| `cmd/govweave/` | 命令行、启动、锁和退出 |
| `internal/config/`、`internal/instance/` | 部署校验、覆盖规则、实例持久化与锁 |
| `internal/auth/` | 密码、限流、会话 |
| `internal/gateway/` | 连接、应用、凭证、策略、转发、流式处理、调用记录 |
| `internal/server/`、`internal/server/web/` | HTTP 管理接口、控制台和本地翻译 |
| `api/`、`schemas/` | 接口与数据契约 |
| `tests/` | SDK、浏览器、容器及语言检查 |

修改文档后检查相对链接、标题锚点和示例语法；修改打包清单后检查离线归档的文档完整性。文档改动无需无条件重复全部运行时测试。当前没有已纳入仓库的 CI 工作流，不应把本地验证描述为 CI 认证。

策略历史测试位于 `internal/gateway/policy_history_test.go`，覆盖不可变读取、稳定分页、重启持久化、旧格式迁移、缺失版本、损坏文件、写入失败与容量上限。浏览器验收覆盖调用详情中的历史快照、缺失历史提示与重试、语言切换及重启持久化。

通用合规引擎测试覆盖三值逻辑、适用性、精确数字比较、证据时效／来源／类型、非法表达式、插件隔离及启动失败、版本绑定、并发评估与管理 API 边界。证据均为虚构测试材料；窄范围欧盟草案验证路由、人工复核与证据区别，不代表全面法规覆盖或审核批准。`internal/governance/` 另覆盖资料持久化、版本冲突、运行证据覆盖拒绝、事件触发、来源失效、到期、重启和缺失规则包；本地二进制验收还包含欧盟草案发现项、不可变快照、固定时间重放及插件／产品变更和重启。归档测试另覆盖私有持久化、损坏、边界、写入失败、并发保存和不支持的引擎版本。

`make validate-routing` 通过版本固定的检测器注册表，在新 60 例上回放冻结的快慢路径策略，分开记录标签效果与深度参考一致性；门控跳过深检保持未知。接口、源码冻结流程、调用计数及计时边界见[检测器插件与分流回放](detector-routing.md)。

`make validate-sensitive` 分别用 v1/v2 离线测量原 80 条与新增 64 条冻结合成样本；`make demo-sensitive` 用本机模型服务验证 v1 原始样式与 v2 混淆样式的真实 HTTP 拦截。仅显式运行 `python3 scripts/demo-sensitive.py --kimi` 才会向 Moonshot 发送三次简短合成请求，隐藏输入密钥，使用临时加密配置并只保存结果元数据。见[敏感输出保护](sensitive-output.md)。

`make demo-output-governance` 使用 8 次模型调用、2 次工具调用和 11 份保留报告验证敏感输出草案包，重放不访问提供方。Go 测试覆盖缺失／不可用证据、范围及类别缺口、旧修订、最大事实预算，以及不依赖读取触发的后台自动重评。见[规则包指南](sensitive-output-governance.md)。

`python3 tests/redaction-smoke.py` 通过真实客户端与本机 HTTP 服务验证工具脱敏、整段凭证替换、独立阻断、未知结果扣留及审计隐私。脱敏功能不修改冻结检测器与样本。

`make demo-output-assessment` 验证敏感输出规则包 1.1.0 下的 35 次本机模型请求、8 份主动测试和 9 份产品报告，见[主动输出控制测评](output-control-assessments.md)。

`make demo-tool-assessment` 验证 `sensitive-tool-governance@1.0.0` 下的 43 次本机工具调用、10 轮主动测试和 9 份报告，覆盖权限扩大与旧凭证拦截优先级，见[主动读取工具测评](tool-control-assessments.md)。

`make demo-application-assessment` 验证同产品两个命名计划、38 次本机调用、9 轮测试与 9 份报告，覆盖独立计划证据失效、共享策略失效和重放，见[同一产品的模型与工具测评](application-assessments.md)。

`make evaluate-agent` 对 12 个冻结合成案例运行宽松／保护对照，分开保存开发／评估指标与真实请求 ID 轨迹。`python3 tests/knowledge-agent-test.py` 覆盖提议校验、拒绝后停止、限额、隐私、故障与未知统计。见[知识库 Agent 行动链测评](knowledge-agent.md)。

`make evaluate-agent-controls` 在单独冻结的 v2 语料上运行原有和新增控制配置。后者启用工具指令检查及精确公开邮箱许可。应同时保留两组报告，包括引用攻击的培训材料误拦结果。

`make evaluate-agent-reviews` 在冻结 v3 案例上分别运行指令 v1、v2、v2 加精确文档许可。`python3 tests/document-review-test.py` 检查有界的本机核验元数据命令。检测器和许可需明确配置；应同时保留三组报告，区分语法覆盖与管理员许可的作用。

`make accept-agent` 在三组保护配置下执行全部七个冻结验收案例。`python3 tests/agent-acceptance-test.py` 无需外部调用，检查计划分母、归因、全局准入预算、私有凭证文件及提供方预检错误脱敏。验收入口支持有界重复与显式真实模式，本机与有界 Moonshot 实测分开记录。调用间隔通过模拟时钟及实际本机 HTTP 验证，没有添加自动重试。见 [Agent 验收](knowledge-agent.md#三组配置的有界验收)。

`make validate-sensitive-v3` 对冻结的 45 条格式／编码语料测量 v2 与 v3，再用两批历史语料验证 v3。v1／v2 源码继续冻结，新实现位于 `internal/sensitive/v3.go`，通过 `Scan`／`Supports` 注册分发。`go test ./internal/sensitive -run '^$' -fuzz FuzzV3BoundedFindings -fuzztime=5s -parallel=2` 检查任意输入的范围与边界。验收入口可加 `--sensitive-detector sensitive-text-v3`，默认仍为 v2。

`make validate-task-grading` 不调用模型，仅测量冻结评分器样例。`python3 tests/task-grading-test.py` 检查开发分区、证据前提、输入上限及元数据隐私。验收报告保留字面评分，并单独增加 `task-facts-v1`；未来增加评分版本时需保留其[源码冻结](../../tests/testdata/task-grading-v1-source-freeze.json)。

`python3 tests/support-agent-test.py` 验证独立客服应用、私有轨迹、凭证隔离、证据归因、调用准入及实际本机知识库鉴权，需要临时回环端口。`make demo-support-agent` 执行九个试用案例和 20 组本机耗时对照；已知十六进制失败对应退出码 3。本机与真实证据见[试用指南](support-agent-trial.md)。

`make demo-multi-agent-trace` 通过隔离的本机网关运行合成 Python/Node 进程示例：五次工具调用、三次上游读取、两次拒绝、汇合、重试和应用查询隔离。`python3 tests/trace-client-test.py` 检查不可变上下文、逐调用及逐 Agent 运行隔离、服务端回执和模型 → 工具 → 模型串联。Go 测试覆盖三个追踪入口、鉴权变更、审计故障、历史窗口、重启及记录大小限制。这些检查不证明框架兼容或完整任务正确性，见[异构 Agent 追踪](agent-tracing.md)。

可选的[真实框架联调](framework-tracing-trial.md)在独立环境固定 LangGraph 与 Pydantic AI 版本。安装对应依赖后执行 `make trial-framework-trace FRAMEWORK_PYTHON=/path/to/venv/bin/python`，并用该解释器运行 `tests/async-trace-client-test.py`、`tests/framework-adapters-test.py` 和 `tests/framework-trial-test.py`；最后一组检查失败后的任务清理、满队列关闭及私有失败报告。此套件不为 Go 运行时或普通 Python 示例新增框架依赖。
