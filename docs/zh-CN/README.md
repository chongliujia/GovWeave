# GovWeave 文档

[English](../README.md) | **简体中文**

这些文档描述 **0.2.0-dev** 已实现的单实例网关。首次使用请从[项目首页](../../README.zh-CN.md)开始。英文文档是默认版本，中文文档保留相同的接口标识、配置方式与能力边界。

## 按任务阅读

| 任务 | 文档 |
| --- | --- |
| 用 BASE URL、应用密钥和模型别名接入自己的应用 | [应用接入指南](application-onboarding.md) |
| 留存加密风险证据、复核处理前后输出与查询证据关系 | [风险证据](risk-evidence.md) |
| 测量已知标记泄露检测，查看漏检样本 | [标记检测与验证](canary-validation.md) |
| 比较检测阶段效果与本机调用耗时 | [效果与成本回测](canary-benchmark.md) |
| 扩展文本检测器，验证快慢路径分流 | [检测器插件与分流回放](detector-routing.md) |
| 没有真实模型或应用，体验完整测评 | [本机演示](local-demonstration.md) |
| 部署二进制或容器，配置地址、HTTPS、备份和恢复 | [部署与运维](deployment.md) |
| 检测敏感文本，保护非流式模型回答与工具输出 | [敏感输出保护](sensitive-output.md) |
| 用实际调用证据评估输出保护并保留报告 | [敏感输出技术控制包](sensitive-output-governance.md) |
| 主动验证模型输出保护并关联两阶段测试证据 | [主动输出控制测评](output-control-assessments.md) |
| 验证读取工具输出保护、越权拒绝及两阶段证据 | [主动读取工具测评](tool-control-assessments.md) |
| 在同一产品报告中评估模型与工具 | [同一产品的模型与工具测评](application-assessments.md) |
| 运行有界知识库 Agent，比较攻击结果与正常任务效果 | [知识库 Agent 行动链测评](knowledge-agent.md) |
| 试用独立客服应用，替换知识资料并测量本机读取耗时 | [独立客服 Agent 试用](support-agent-trial.md) |
| 追踪异构 Agent 调用、并行分支、汇合与重试，并隔离查询权限 | [异构 Agent 追踪](agent-tracing.md) |
| 验证真实 LangGraph/Pydantic AI 交接、取消和缺失回执 | [真实框架追踪联调](framework-tracing-trial.md) |
| 接入应用或 Agent 平台的只读工具、Python 执行器及产品评估 | [只读工具治理](tool-governance.md) |
| 接入 AI 应用或 Agent 的模型客户端 | [模型接入](model-gateway.md) |
| 理解流式响应、错误、记录和容量限制 | [模型运行边界](model-gateway.md#流式超时与错误) |
| 安装声明式规则包，评估产品证据 | [通用合规引擎](compliance-engine.md) |
| 登记产品并自动评估网关证据 | [产品持续评估](product-assessments.md) |
| 审查欧盟透明度草案并保存／重放报告 | [欧盟草案与报告快照](eu-transparency-reports.md) |
| 执行部署前及周期复测，查看 NIST 生命周期证据 | [主动测评](active-assessments.md) |
| 配置凭证检测、范围和观察／阻断模式 | [运行时策略](runtime-policies.md) |
| 编译、测试或修改控制台 | [开发与验收](development.md) |
| 自动化管理和查看数据契约 | [OpenAPI](../../api/openapi.yaml) 与 [Schema](../../schemas/) |

## 当前实现

应用或 Agent 的模型客户端发送请求后，网关依次校验应用身份和模型授权、执行适用的本地凭证检查、持久化开始记录并预留结束容量，再根据策略决定阻断或访问模型。默认输出策略关闭，流式回答按事件转发，结束时记录结果。启用独立[敏感输出保护](sensitive-output.md)后，完整非流式文本会在检查与记录决定后返回，流式请求在上游 I/O 前拒绝。认证、输入校验、并发限额和记录故障也可提前停止请求。

另有[只读工具调用流程](tool-governance.md)：执行前校验应用与资源授权，返回文本检查凭证样式，持久化终态决定后才释放输出。

控制台、策略检查与转发在同一个 Go 进程中运行。配置和元数据保存在本地私有文件，不依赖 PostgreSQL、外部策略引擎、云端控制面或遥测收集器。数据目录通过单实例进程锁保护，不支持多进程或多主机共享。模型可以是内网服务，也可以是配置的云端上游。

## 架构决策

| 决策 | 内容 |
| --- | --- |
| [ADR 0001](adr/0001-gateway-first.md) | 自部署网关基础；原管理员认证和 Go 基线已被后续决策替代 |
| [ADR 0002](adr/0002-model-gateway.md) | 模型适配、应用密钥、流式转发和持久化调用记录 |
| [ADR 0003](adr/0003-password-login.md) | 初始管理员密码与浏览器会话 |
| [ADR 0004](adr/0004-request-credential-policy.md) | 上游调用前的本地凭证检测 |
| [ADR 0005](adr/0005-policy-history.md) | 凭证策略历史原子保存与请求版本追溯 |
| [ADR 0006](adr/0006-declarative-compliance-engine.md) | 通用技术评估引擎与声明式规则包插件 |
| [ADR 0007](adr/0007-product-evidence-assessments.md) | 产品资料、网关证据和自动重评 |
| [ADR 0008](adr/0008-regulatory-draft-report-snapshots.md) | 法规草案、人工发现项和报告输入留存 |
| [ADR 0009](adr/0009-active-lifecycle-testing.md) | 主动测试、显式周期复测和部分 NIST 支撑 |
| [ADR 0010](adr/0010-scoped-risk-evidence.md) | 显式应用范围的加密正文证据与运行记录引用 |

[早期产品草案](archive/initial-design.md)已归档。其 Eval 优先、假设已有 GRC 产品以及 Python/TypeScript 总体方案不代表当前实现。

[贡献者与编码 Agent 指南](contributing.md)

## 后续规划

MCP 执行控制、审批、更多检测器、连接／应用配置历史和人工审核的 EU/US 法规映射仍属后续工作。此列表不构成交付日期或法律覆盖承诺。各功能的具体限制以对应指南为准。

文档中的回环地址用于本机测试，`.example` / `example.com` 域名只是占位符。企业需配置真实网络地址、证书和上游模型；GovWeave 不自动提供这些资源。
