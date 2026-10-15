# 开发与验收

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

## 当前支持范围

Linux 构建和运行路径已作为主要目标；macOS 的文件锁和打包分支尚需平台 CI 验证，Windows 不支持当前文件锁实现。模块语言版本是 1.24，生产分发应使用受支持的安全更新工具链，Docker 构建固定 Go 1.26.9。

MCP、法规检测、生产性能与 HA 尚未验收；真实云厂商兼容性尚未验证，不能依据本地模拟测试宣称全面兼容。

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
