# GovWeave

企业自部署的 AI 治理网关。当前交付 **模型接入预览版（0.2.0-dev）**，贯通模型连接、应用授权、请求凭证检测、普通／流式调用和本地调用记录。

## 当前可以做什么

- 无云端账号注册，首次设置管理员密码即可使用；本地控制台与静态资源随 Go 二进制分发。
- 控制台默认英文，支持即时切换简体中文并记住语言偏好；所有语言资源随程序离线提供。
- 企业配置自己的访问地址，自动生成模型 BASE URL 和实际接入示例。
- 配置 OpenAI 兼容的模型连接、上游凭证、企业模型别名、启用状态和超时。
- 创建应用、授予模型权限、生成一次性展示的 API Key，并轮换或撤销。
- 提供 `POST /v1/chat/completions`（普通 JSON / SSE）和 `GET /v1/models`。
- 运行时策略中心可按应用和模型范围检查请求中的私钥标记及部分 API 密钥样式；默认关闭，支持观察与阻断。
- 保存应用、模型别名、请求 ID、授权决定、执行结果、耗时和配置版本；不保存提示词、回答或凭证。
- 上游凭证使用 AES-256-GCM 加密保存；应用密钥只持久化 SHA-256 哈希与识别前缀。

**通用敏感数据识别、响应内容检测、MCP 执行、审批、EU/US 法规映射、完整企业 IAM 和 HA 尚未实现。** 当前的 allow/deny 仅表示模型访问授权，不代表法律合规结论。未支持的模型和 MCP 接口返回 `501`。

## 启动与第一次调用

源码开发需要 Go 1.24+；分发构建请使用受支持且包含安全更新的 Go 版本（Docker 固定 1.26.9）。服务无第三方 Go 模块和前端构建依赖。

```bash
go run ./cmd/govweave -config examples/deployment.json
```

1. 打开 `http://127.0.0.1:8080`，首次设置并确认管理员密码（12–128 个字符），即可进入控制台；以后使用该密码登录。请先完成此步骤，再开放给其他用户访问。
2. 在“部署与接入”填写组织和实际根访问地址，保存配置。
3. 在“模型连接”填写上游 BASE URL、真实模型 ID、凭证和企业别名（例如 `internal-assistant`）。本地无鉴权模型可不填凭证；HTTP 上游需要明确勾选允许。
4. 在“应用与密钥”创建应用，勾选允许使用的模型，保存只展示一次的应用密钥。
5. 回到“部署与接入”，选择该应用并复制示例。将应用密钥设置为调用程序的 `GOVWEAVE_API_KEY`，再执行示例。
6. 可选：在“运行时策略 / Runtime policies”配置凭证检测，先观察命中，再按需启用阻断。观察模式仍转发原始请求及其中凭证。
7. 在“调用记录”刷新查看结果。连接检查仅调用上游 `GET /models`，实际推理须通过应用调用验证。

离线二进制包解压后用 `./govweave -config examples/deployment.json` 启动。网关可离线安装；推理需要可达的企业本地模型或已配置的外部服务。选择外部服务时，请求内容会发送给该上游。

详见 [部署与配置](docs/deployment.md)、[模型接入与运行边界](docs/model-gateway.md)。

## 开发验证

```bash
make test
make check
make build
make package
```

`make test` 使用 race detector，需要 C 编译器和本机临时端口权限；测试仅连接本地模拟服务。`make check` 需要 Node 检查脚本语法；构建和运行无需 Node。浏览器、真实 SDK 和容器验收见 [开发与验收](docs/development.md)。

## 设计与接口

- [ADR 0001：自部署网关入口](docs/adr/0001-gateway-first.md)
- [ADR 0002：模型访问与调用记录](docs/adr/0002-model-gateway.md)
- [ADR 0003：管理员密码与浏览器会话](docs/adr/0003-password-login.md)
- [部署 Schema](schemas/deployment.schema.json)、[实例更新 Schema](schemas/instance.schema.json)、[连接与应用 Schema](schemas/gateway.schema.json)
- [OpenAPI 契约](api/openapi.yaml)

`agent.md` 是早期草案，其“Eval 优先、已有 GRC”前提已更新，以 ADR 为准。后续继续建设 MCP 工具执行边界和经过人工审核的 EU/US 法规控制映射。

采用 [Apache-2.0](LICENSE)；分发依赖许可见 [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES)。
