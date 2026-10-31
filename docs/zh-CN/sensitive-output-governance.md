# 敏感输出技术控制包

[English](../sensitive-output-governance.md) | **简体中文**

内部策略草案 [`sensitive-output-governance@1.0.0`](../../examples/rule-packs/sensitive-output-governance.json) 将[输出保护](sensitive-output.md)、产品评估和报告留存连接起来。它依据网关配置和实际模型／工具调用的元数据进行评估，不会自动开启策略、修改模式，也不宣称满足某部法律或外部标准。

## 安装与登记

将包复制到实例的规则目录后重启。示例部署使用：

```bash
mkdir -p data/rule-packs
cp examples/rule-packs/sensitive-output-governance.json data/rule-packs/
go run ./cmd/govweave -config examples/deployment.json
```

用真实应用 ID 替换 [`examples/sensitive-output-product.json`](../../examples/sensitive-output-product.json) 中的占位值，再通过 `POST /api/v1/compliance/products` 登记。鉴权与接口见[产品登记](product-assessments.md)。产品资料不能提交 `runtime.*` 事实，这些事实由网关采集；独立的无状态评估接口仍接受调用者提供的来源标签，不能代替可信采证。

管理员另外配置 `sensitive-output`：选择 `block` 或 `redact`，开启 credential、email、phone，并覆盖全部绑定应用。检测器版本仍由管理员显式选择。每次修改后，应通过授权的合成模型／工具调用验证新修订；独立文本评估不能证明实际执行链路有效。

## 八项控制

| 控制项后缀（统一前缀 `OUTPUT-`） | 要求 |
| --- | --- |
| `APPLICATIONS-ACTIVE` | 所有绑定应用存在且未撤销 |
| `PROTECTIVE-MODE` | 输出模式为阻断或脱敏 |
| `SCOPE-COVERAGE` | 已启用策略覆盖全部绑定应用 |
| `CATEGORY-COVERAGE` | 凭证、邮箱、中国大陆手机号码三类检查均开启 |
| `AUDIT-AVAILABLE` | 持久化审计写入及容量预留可用 |
| `CURRENT-EVIDENCE` | 至少一个实际模型／工具输出在当前策略修订和检测器版本下完成检查 |
| `SAMPLE-RELEASES` | 有界样本中没有检出后观察放行，也没有缺少三类完整检查的放行 |
| `SAMPLE-COMPLETENESS` | 样本中没有未知输出评估，也没有重启后恢复的未完成调用 |

最后两项可以在空样本上通过，但此时 `CURRENT-EVIDENCE` 失败，整体不会显示全部满足。审计不可用时不生成样本事实，对应控制项为 `unknown`，审计可用性检查失败。绑定应用不存在时，其配置覆盖保持未知。

一次检查并不代表所有应用、风险类别、模型、工具和调用路径都已验证，更不能代表检出率。阻断已检出的输出、成功脱敏后返回，都可以提供执行证据；失败检查、待完成状态和独立接口返回的脱敏建议不可以。

## 证据字段

以下字段统一以 `runtime.` 开头、来源为 `runtime`。配置证据引用网关及输出策略修订；样本证据引用采集时审计文件的字节位置，当前策略检查证据还引用策略修订。

| 字段后缀 | 含义 |
| --- | --- |
| `output_policy_revision`、`output_policy_mode` | 精确策略修订及模式 |
| `output_policy_covers_product` | 已启用策略覆盖全部绑定应用；类别和模式是否满足要求分别检查 |
| `output_detector_version` | 固定的敏感文本检测器版本 |
| `output_credential_enabled`、`output_email_enabled`、`output_phone_enabled` | 三类检查分别是否选中 |
| `sample.output_current_checked_count` | 当前策略修订和检测器版本下，实际尝试执行并以完整 observed／not_observed 检查结束的模型／工具调用数 |
| `sample.output_block_count` | 以 `content_output_blocked` 拒绝的调用；旧工具凭证拦截另有计数 |
| `sample.output_redacted_count` | 返回成功、结果为 `redacted` 且具有脱敏完成证据的次数 |
| `sample.output_observed_release_count` | 返回成功且输出策略结果为 `observe` 的次数 |
| `sample.output_unchecked_release_count` | 已放行但缺少完整敏感输出检查，或未覆盖全部三类的次数；包括旧记录、关闭策略和范围外调用 |
| `sample.output_unknown_count` | 输出策略结果为 `error` 的已结束调用，包括不支持的流式请求及无法取得输出 |
| `sample.output_incomplete_count` | 重启后恢复为未完成的绑定模型／工具调用 |

样本从**全局最近 100 条审计记录**中筛选产品绑定应用及 `chat.completions`／`tools.invoke`，排除 `content.evaluate` 和 `assessment.chat.completions`。它既不是时间窗口，也不是全部历史。其他应用的流量可能挤出旧证据，因此不能作为永久事件台账。进行中的调用尚无最终结论；聚合事实的观察时间表示采集时间，不代表其中调用发生于近期。

策略修改后，旧放行记录仍保留在这个有界样本中；旧修订的检查不能验证新修订。未检查放行是证据缺口，不能直接说成泄露；未知输出也可能已被安全拦截。只有显式保存的报告快照，才能在证据离开实时样本后继续保留当时状态。

## 本机演示

```bash
make demo-output-governance
```

命令使用隔离的本机服务与临时私有实例，执行 8 次脚本化模型调用、1 次独立文本评估和 2 次工具调用。在 `dist/output-governance-demo/<唯一运行目录>/` 保存 11 个阶段的报告快照和摘要。无需外部 API 或真实密钥，只留元数据；策略继续变化后逐一重读旧报告并重放，结果必须一致且不能新增提供方调用。

| 部分阶段 | 通过／失败 |
| --- | --- |
| 关闭策略且没有调用 | 5／3 |
| 阻断模式，仅独立文本评估 | 7／1 |
| 阻断模式，实际检查输出 | 8／0 |
| 新脱敏修订，尚未调用 | 7／1 |
| 脱敏模式，实际替换并返回 | 8／0 |
| 观察模式放行合成邮箱 | 6／2 |
| 此后恢复阻断 | 7／1 |
| 工具阻断／工具脱敏，独立干净样本 | 各 8／0 |

工具演示明确将旧凭证控制设为观察，以验证新策略的阻断／脱敏行为；实际配置为旧凭证阻断时仍由旧控制优先拒绝。模型演示还验证关闭策略后的未检查放行，以及恢复保护后该缺口继续保留。报告始终标明 `evaluation_only: true`、`legal_compliance: not_determined` 和草案状态。这些测试证明接入和证据语义，不能证明真实业务检出效果或法律合规认证。

可选版本 1.1.0 增加当前计划的部署前及运行期探测要求，见[主动输出控制测评](output-control-assessments.md)，可用 `make demo-output-assessment` 复现；下文 1.0.0 保持不变。
