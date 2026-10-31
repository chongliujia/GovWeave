# 主动输出控制测评

[English](../output-control-assessments.md) | **简体中文**

可选的 `sensitive-output-governance@1.1.0` 在原有[八项运行控制](sensitive-output-governance.md)上增加两项主动测试要求：测试计划指定的模型目标，必须分别具备部署前和运行期的有效输出保护证据。1.0.0 保留原来的八项控制，现有产品不会自动升级。

## 安装与配置

```bash
mkdir -p data/rule-packs data/test-suites
cp examples/rule-packs/sensitive-output-governance-v1.1.json data/rule-packs/
cp examples/test-suites/sensitive-output-controls.json data/test-suites/
```

重启实例加载这两个本地 JSON 插件。用[产品示例](../../examples/sensitive-output-assessment-product.json)绑定真实应用与规则包 1.1.0；更新现有产品时提交当前修订号。用[测试计划示例](../../examples/sensitive-output-test-plan.json)填写绑定应用 ID 和已授权模型别名，再通过 `PUT /api/v1/compliance/products/{id}/test-plan` 保存。

另行配置 `sensitive-output` 的检测器版本、全部三类风险及应用范围。阻断和脱敏都可以满足保护测试。独立的请求凭证策略继续生效；内置凭证挑战要求模型拼接两个片段，避免在请求中发送完整凭证样式字符串而被提前拦截。

分别向 `POST /api/v1/compliance/products/{id}/test-runs` 提交 `{"phase":"pre_deployment"}` 和 `{"phase":"operation"}`，随后按返回的运行 ID 查询完成结果。每次新运行调用模型四次，重放不调用模型。定期运行使用现有 `schedule_enabled` 显式开关，可能产生提供方用量；示例默认关闭。鉴权、限额和调度见[主动测评](active-assessments.md)。

## 四项测试证明什么

| 检查 | 必需证据 |
| --- | --- |
| 凭证 `output_protected` | 网关实际检出该类别，并完成阻断或脱敏 |
| 邮箱 `output_protected` | 对邮箱满足同样要求 |
| 中国大陆手机号 `output_protected` | 对手机号满足同样要求 |
| `output_allowed` | 精确返回正常对照文本，且没有敏感发现或内容替换 |

两种新检查均使用 `scope: gateway_control`。`output_protected` 必须指定 `category: credential`、`email` 或 `phone`，不接受预期字面值；`output_allowed` 必须指定精确 `expected`，不接受类别。结论依据进程内部网关执行回执与确认写入的结束审计，不依据模型自称已安全处理，也不接受上游伪造的拦截错误。

观察放行判失败，执行后发现保护未启用也判失败。模型执行前请求被拒绝、审计不可用、上游故障和未知检测保持未验证。如果模型拒答，或没有产生可检出的目标类别，该项为 **unknown**，即使调用方没有收到敏感内容也不能算保护成功。正常对照中，模型未按要求回答保持未知；确认发生输出阻断或替换则判失败。

完整套件必须包含三类挑战和正常对照，缺项不能提供生命周期证据。每项仅请求一次，四项通过不代表检出率、攻击成功率或真实业务准确率。覆盖只限当前计划的应用和模型；其他模型、绑定应用、工具和路径需要另外验证。[主动读取工具测评](tool-control-assessments.md)提供独立工具目标及证据命名空间。每产品可以保留一个模型计划和一个读取工具计划，见[同一产品的模型与工具测评](application-assessments.md)。

## 产品报告与证据有效期

服务器把以下事实合入当前产品评估及显式保存的报告：

| 事实 | 有效期 |
| --- | --- |
| `testing.output.pre_deployment.passed` | 对应运行完成后 30 天 |
| `testing.output.operation.passed` | 对应运行完成后，测试计划运行间隔的两倍 |

来源为 `assessment`，证据 ID 指向测试运行，并保留原始完成及到期时间。主动测试自己的规则评估也包含这些事实。产品资料不能提交或覆盖它们。已完成且结论明确时生成 true／false；最新记录缺失、过期、进行中、中断、执行错误或结论不充分时，没有可用的阶段结论。适配器只选择各阶段最新记录，不向前寻找旧的通过结果。

证据必须匹配当前产品修订、计划修订、测试套件摘要、规则包摘要、执行器版本、模型连接，以及网关／请求策略／工具／输出策略配置。任一变化都会使旧成功失效。保存计划、启动和完成测试会触发后台重评；读取过期缓存时返回 pending，不附带旧评估。来源快照可选字段 `test_evidence_revision` 是进程内缓存代次，不能作为跨重启证据标识。重启后从保存的运行记录重建当前证据。

主动请求仍标为 `assessment.chat.completions`，**不会增加生产调用证据计数**。因此四项主动测试全通过，仍可能缺少前八项控制要求的实际业务调用证据。主动请求会占用全局最近 100 条审计索引，可能挤出旧业务样本。报告仍是建议性评估，不自动拦截部署或修改策略。

## 留存、重放和验证

执行器 `bounded-chat-tests-v4` 增加这些检查，并保留旧版本记录的读取／重放；canary 检测器 v2 不变。不同执行器版本不共享生命周期证据。新输出控制用例只保留有界网关决策元数据，即使 `retain_responses: true` 也不保存返回正文。正常对照保留摘要与字节数用于精确比对，类别挑战不保留正文摘要。测试套件的提示词和预期字面值仍会保存，因此请使用合成数据。

产品报告快照保留标量事实及运行引用，逐项证据位于独立测试记录，备份应同时包含两者。重放仅复算保存的规则结论，不调用模型，也不宣称仅凭元数据重新验证检测效果。私有文件摘要能检查变化，但不是签名。

```bash
make demo-output-assessment
```

隔离演示向脚本化本机模型发起 35 次请求：3 次普通正常调用，以及 8 轮、每轮 4 项的主动测试。在 `dist/output-assessment-demo/<唯一目录>/` 保存 9 份产品报告和 8 份测试记录。验证仅有运行证据时为 8 通过／2 未知，两阶段成功后为 10 通过，拒答或版本变化后恢复未知，观察模式下出现 3 项失败。所有保存的报告和测试评估均须重放一致，且不新增提供方调用，无需外部 API 密钥。Go 测试另覆盖审计失败、伪造上游拦截、进行中状态、来源变化、到期、重启及证据校验。
