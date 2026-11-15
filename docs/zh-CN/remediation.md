# 风险整改与验证

[English](../remediation.md) | **简体中文**

整改记录把产品评估中的控制缺口或未知结果，与处理进展、新评估及可选的模型／工具复测证据关联起来。入口为**插件中心 → 合规框架与规则包**，也可使用[命令行管理](admin-cli.md)。第一版面向产品评估控制项，不会自动把每次请求阻断都转换为事件工单。

## 控制台流程

1. 选择已保存的产品并评估，展开失败或未知控制项，点击**跟进整改**。服务端先留存新的评估，再根据其中的确切控制项建立记录；如果控制项已经通过，则拒绝创建。创建记录失败时，已保存的报告可能仍在归档中，请先加载记录再决定是否重试。
2. 在**风险整改与验证**中填写负责人／团队、可选目标日期和说明。这些是操作人员声明，不代表已认证分派、通知或审批。说明中不要填写密钥、提示词或回答正文。
3. 通过相应策略、产品或应用配置完成实际修改，再填写说明并保存为**待复核**。这个状态只表示处理工作准备就绪，不等于已验证修复。
4. 需要模型／工具复测时，在标记待复核之后显式运行已配置的测试。**打开模型测试**进入现有计划与执行面板；读取整改记录不会启动测试。运行完成后重新加载整改记录，可选择关联该次测试。后端核对产品、当前配置和计划版本，以及是否在待复核事件后启动；运行中、过早、跨产品或过期测试被拒绝。失败或结论不明的测试不能验证关闭问题。
5. 点击**复核证据并验证**。它使用当前证据进行新的本地评估并保存报告，不调用模型或工具。只有原控制项为 `pass`，且可选关联测试也通过，才进入**已在记录的快照中验证**。`fail`、`unknown`、`not_applicable` 均回到**整改中**。人工审核控制项仍保持未知，此功能不会代替审核批准。

复核要求原规则包指纹和完整应用集合保持一致。修改产品版本或证据事实可以属于整改，但更换规则包或移除问题应用不能关闭原发现。新规则包／范围应建立单独记录。同一产品、控制项、规则包和应用集合只保留一条整改记录，再次处理时重新打开原记录。

## 历史验证与当前证据

处理状态为 `open`、`in_progress`、`ready_for_recheck`、`verified`。普通更新只能设置前三种；已验证记录须先回到 `open`。每次成功写入追加一个事件，保留当时的负责人、日期和说明，API 不会改写旧说明或旧验证引用。

读取记录时另行计算 `verification_state`：

| 状态 | 含义 |
| --- | --- |
| `not_verified` | 当前处理事件尚未验证通过 |
| `current` | 留存证据在读取时仍通过，且符合当前来源版本 |
| `stale` | 产品、网关、策略、工具、测试证据、审计样本或证据有效性已变化 |
| `unavailable` | 引用的验证证据无法核实 |

证据变化后，历史 `verified` 事件仍然保留；只有同时满足 `verification_state: current` 才能作为读取时的有效验证。发生变化后应重新加载，这不是持续监控或部署放行。版本判断较保守：其他网关修改或新审计流量也可能触发重新复核。关联的运行期测试有效期为计划间隔的两倍，部署前测试为 30 天；规则事实可能更早过期。

**查看原始发现**和**查看验证报告**展示对应留存控制项及证据引用。报告保留原评估时间，可用既有归档 API 重放。可选复测通过不可变 ID 和摘要关联，整改文件不复制测试提示词或回答。一次通过的复测只覆盖声明的目标和测试集，不代表所有应用或风险均已验证。技术验证不构成法律合规认证。

## CLI 与 API

先按[命令行指南](admin-cli.md)登录，以下 `gw` 表示其中绑定会话的 shell 函数。大写 ID 和修订号示例都须替换为实际返回值。

```bash
gw products list
gw reports create --product PRODUCT_ID
umask 077
cat > remediation-create.json <<'JSON'
{"report_id":"REPORT_ID","control_id":"CONTROL_ID","owner":"平台团队","due_date":"","note":"调查未满足的控制要求"}
JSON
gw remediations create --product PRODUCT_ID --file remediation-create.json
gw remediations list --product PRODUCT_ID
```

更新文件使用私有权限，包含 `revision`、`status`、`owner`、`due_date`、`note`，随后执行：

```bash
gw remediations update --product PRODUCT_ID --id REMEDIATION_ID --file remediation-update.json
gw tests plans --product PRODUCT_ID
# 此命令明确启动已配置的模型或工具调用：
gw tests run --product PRODUCT_ID --plan PLAN_ID --phase operation
gw tests list --product PRODUCT_ID
gw tests show --id TEST_RUN_ID
gw remediations recheck --product PRODUCT_ID --id REMEDIATION_ID --revision 2 --test-run TEST_RUN_ID
gw remediations show --product PRODUCT_ID --id REMEDIATION_ID
```

省略 `--test-run` 时，仅使用评估已有的证据来源进行本地复核；规则包自身要求的主动测试证据仍然必须满足。`tests run` 只启动现有计划，不等待完成，也不重试失败调用。计划可通过网页模型测试面板或原有测试计划 API 配置。API 兼容旧的空计划 ID，CLI 使用具名计划。

管理员接口为 `GET/POST /api/v1/compliance/products/{id}/remediations`、`GET/PUT .../remediations/{remediation}`、`POST .../remediations/{remediation}/recheck`。输入输出见 [OpenAPI](../../api/openapi.yaml) 和[整改契约](../../schemas/remediation.schema.json)。写入使用整改最新事件的修订号，与策略修订号独立。管理员认证、严格 JSON、16 KiB 请求上限和 Origin／自定义请求头校验均适用。应用密钥不能访问这些记录；发生冲突或写入结果不确定时不会自动重试。

## 持久化与验收

`remediations.json` 以 `0600` 权限原子保存，最多 128 条记录，每条最多 64 个事件，总上限 2 MiB。说明最多 2000 UTF-8 字节，负责人标签最多 100 字节。文件未加密，也不构成防篡改审计服务。没有删除／裁剪接口或自动驱逐；容量不足时保留已有历史。每次复核占用普通报告归档容量，受其 256 份／64 MiB 上限约束；若报告已保存而后续整改写入失败，报告仍保留。

停机备份时，将该文件与产品配置、`assessment-reports/`、`test-runs/`、测试计划及其他数据目录文件一起保存。启动会验证事件顺序、状态转换和引用证据，不会静默重置损坏历史。不支持只恢复整改文件而缺少其引用的报告／测试。

Go 测试覆盖失败／未知／不适用结果、范围和版本绑定、显式本机模型复测、并发冲突、容量、持久化失败、损坏、过期、重启及 API／CLI 管理权限。`node tests/plugins-smoke.cjs` 验证真实网页流程、安全文本渲染、语言切换、移动布局、陈旧证据、迟到响应、退出清理和重启。均使用合成数据，不访问真实外部提供方。
