# 同一产品的模型与工具测评

[English](../application-assessments.md) | **简体中文**

一个产品现在可以同时维护一个模型测试计划和一个读取工具测试计划。两者的当前生命周期证据进入同一份产品报告，分别保留运行 ID、计划修订和过期时间。可选规则包 `application-output-governance@1.0.0` 检查十三项技术控制：八项运行输出控制、资源授权覆盖、两项模型生命周期检查和两项工具生命周期检查。

## 配置两个计划

安装组合规则包及两个测试套件，然后重启：

```bash
mkdir -p data/rule-packs data/test-suites
cp examples/rule-packs/application-output-governance.json data/rule-packs/
cp examples/test-suites/sensitive-output-controls.json data/test-suites/
cp examples/test-suites/read-tool-output-controls.json data/test-suites/
```

用实际应用 ID 登记[产品示例](../../examples/application-assessment-product.json)。按[模型输出测评](output-control-assessments.md)和[读取工具测评](tool-control-assessments.md)配置授权模型、五个专用合成工具资源及输出策略。保存计划不会自动修改策略或调用提供方。

以下接口沿用管理员会话与写入请求头：

| 接口 | 用途 |
| --- | --- |
| `GET /api/v1/compliance/products/{id}/test-plans` | 列出至多两个计划，包含已有默认计划 |
| `GET, PUT /api/v1/compliance/products/{id}/test-plans/model` | 命名模型计划，采用[模型计划输入](../../examples/sensitive-output-test-plan.json) |
| `GET, PUT /api/v1/compliance/products/{id}/test-plans/read_tool` | 命名工具计划，采用[工具计划输入](../../examples/read-tool-test-plan.json) |
| `POST /api/v1/compliance/products/{id}/test-runs` | 执行明确指定的计划与阶段 |

计划 ID 位于 URL，不放在保存请求体中。每个计划独立维护乐观锁 `revision`，首次为零，更新使用返回的修订号。`model` 要求模型套件及模型字段；`read_tool` 要求 `target_kind: read_tool`、工具套件和工具字段。同一目标类型只能有一个计划，包含已有默认计划；重复时返回 `409 test_plan_target_conflict`。

依次启动以下四轮，每次等待返回的运行 ID 完成后再发下一次：

```json
{"plan_id":"model","phase":"pre_deployment"}
{"plan_id":"model","phase":"operation"}
{"plan_id":"read_tool","phase":"pre_deployment"}
{"plan_id":"read_tool","phase":"operation"}
```

每行是一次独立请求的正文。一次请求只执行选中的计划，不自动扩展到另一个目标。运行摘要与保存的计划包含 `plan_id`；历史列表包含两个计划，客户端可据此分组。

## 已有计划与调度

单数 `/test-plan` 接口继续读写原有默认计划。启动请求不填 `plan_id` 或填空串时，仍只选择默认计划，不会在命名计划之间猜选。产品仅有命名计划时，省略 `plan_id` 返回 404，不访问上游。

旧文件及历史运行摘要保持原有序列化：默认计划没有 `plan_id` 字段。已有模型默认计划时，增加命名 `read_tool`；已有工具默认计划时，增加命名 `model`。不要另建相同目标类型的计划，无需迁移或删除历史证据。

每个计划分别维护周期测试开关、到期时间、最近运行和错误。限额保持全局两轮、每产品一轮，两个计划也不能在同产品内同时运行。调度优先考虑最早到期计划；因产品忙而等待的计划保持到期状态，后续周期继续调度。手动重叠请求返回 `429 test_busy`。只编辑另一个计划不会取消正在进行的测试；编辑当前计划或共享配置则会使本轮失效。

## 报告如何合并

| 证据 | 独立范围 |
| --- | --- |
| `testing.output.pre_deployment.passed`／`testing.output.operation.passed` | 各阶段最新且版本匹配的模型运行 |
| `testing.tools.output.pre_deployment.passed`／`testing.tools.output.operation.passed` | 各阶段最新且版本匹配的工具运行 |

各目标都要求完整类别挑战和正常对照，工具另需拒绝资源检查。最新记录缺失、进行中、中断、过期或结论不足时，不能复用旧成功。只修改模型计划会使模型证据失效，保留仍有效的工具证据，反之亦然。产品或共享网关／请求策略／工具配置／输出策略变化会保守地使两类证据都失效；即使修改无关工具也会改变全局工具修订。部署前证据有效期为 30 天，运行期为对应计划间隔的两倍。

当前产品 `/evaluation` 与保存的 `/reports` 合并两个计划。单次测试记录仍只用本计划事实评估，所以组合规则包中另一个目标的主动控制会显示未知；请查看产品报告获得合并结论。运行证据仍单独计算，主动测试不增加生产计数。全局最近 100 条审计样本、留存限额与重放边界不变。

两个计划可以选择产品已绑定的不同应用，但一个模型计划和一个工具计划不能证明全部绑定应用或路径都已覆盖。这里分别验证选定目标，不是完整 Agent 轨迹。规则包仍是内部技术策略草案，`legal_compliance` 保持 `not_determined`。

## 本机演示

```bash
make demo-application-assessment
```

隔离演示共 38 次本机调用、9 轮主动测试和 9 份产品报告。主动测试前为 9 通过／4 未知，只完成模型测试后为 11 通过／2 未知，再完成工具测试后为 13 通过。修改模型计划保留工具证据；挑战缺失仅影响对应目标／阶段；共享策略变化使两者失效。十八份记录均重放一致且不新增上游访问，保存于 `dist/application-assessment-demo/<唯一目录>/`。这些合成测试验证控制执行和证据管理，不代表真实业务风险覆盖率。
