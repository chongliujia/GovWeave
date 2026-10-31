# 主动读取工具测评

[English](../tool-control-assessments.md) | **简体中文**

可选规则包 `sensitive-tool-governance@1.0.0` 将主动工具测试接入产品报告。共十一项技术控制：原有[八项运行输出控制](sensitive-output-governance.md)、可用资源授权覆盖，以及部署前／运行期工具测试。它是内部策略草案，不代表法规符合性判定。

## 安装与配置

```bash
mkdir -p data/rule-packs data/test-suites
cp examples/rule-packs/sensitive-tool-governance.json data/rule-packs/
cp examples/test-suites/read-tool-output-controls.json data/test-suites/
```

重启加载插件。配置一个[读取工具](tool-governance.md)，提供五个专用合成资源：`probe-credential`、`probe-email`、`probe-phone`、`probe-benign`、`probe-denied`。测试应用获准访问前四个，最后一个不授予权限。提供方分别返回合成凭证／邮箱／中国大陆手机号、精确正常文本 `GOVWEAVE_TOOL_READY`，以及合成受限内容。提供方应遵循已有只读协议，不能仅凭 HTTP 接口名称认定任意上游没有副作用。

用实际应用 ID 登记[产品示例](../../examples/sensitive-tool-product.json)。替换[计划示例](../../examples/read-tool-test-plan.json)中的 `application_id`、`tool_alias`，通过 `PUT /api/v1/compliance/products/{id}/test-plan` 保存。设置 `target_kind: read_tool`，省略 `model_alias` 和 `max_output_tokens`。只使用工具的应用无需模型权限。套件也必须指定 `target_kind: read_tool`，每个用例用 `resource_id` 替代 `messages`。

另行配置 `sensitive-output` 的应用范围、检测器版本和三类风险，选择 `block` 或 `redact`。工具原有凭证检查仍优先：`output_mode: block` 可能在脱敏前扣留凭证，明确记录为 `legacy_tool_credential_blocked`，不记作完成脱敏。如需测试凭证脱敏，应有意将旧检查设为 `observe`，同时保持独立输出策略为 `redact`。

向 `POST /api/v1/compliance/products/{id}/test-runs` 分别提交 `{"phase":"pre_deployment"}` 或 `{"phase":"operation"}`，再按返回 ID 查询完成状态。沿用管理员鉴权和[主动测试限额](active-assessments.md)。周期运行需要显式启用，意味着授权定期访问工具；示例默认关闭。每个产品可以保留一个模型计划和一个读取工具计划，包含已有默认计划。两者同时配置及明确选择命名计划的方法见[同一产品的模型与工具测评](application-assessments.md)。

## 五项测试证明什么

| 检查 | 必需证据 |
| --- | --- |
| 凭证、邮箱、手机号 `output_protected` | 分别实际检出目标类别，并完成阻断或脱敏 |
| `output_allowed` | 精确返回正常文本，且没有敏感发现或内容替换 |
| `tool_denied` | 在访问上游前拒绝指定资源，并成功写入结束审计 |

各项均为 `scope: gateway_control`。启动前要求所有资源已配置，四项输出测试已获授权。拒绝用例的资源可能因权限变化被放行，这是需要检出的条件，因此测试继续执行并判为 `tool_resource_was_authorized`。此时真实权限允许访问上游，所以必须使用合成资源。权限正确时，五项测试只有四次上游读取。执行过程没有伪造应用密钥或接受调用方自报身份来绕过权限。

结论依据内部网关回执和已提交的结束审计；提供方伪造的拒绝错误不能证明网关拒绝授权或阻断输出。观察放行导致保护测试失败。挑战内容缺失、审计不可用或执行无法验证时保持未知；仅收到无害文本不足以证明保护有效。每项只执行一次，覆盖范围限于一个已配置工具和选定资源，不代表全部工具、完整自主 Agent 轨迹、语义正确性、一般隐私保障或检测准确率。

## 产品证据与重放

| 事实 | 完成后的有效期 |
| --- | --- |
| `testing.tools.output.pre_deployment.passed` | 30 天 |
| `testing.tools.output.operation.passed` | 配置运行间隔的两倍 |

来源为 `assessment`，保留原运行 ID 与时间戳，必须完整覆盖五类检查。模型事实 `testing.output.*` 不能满足工具要求，工具事实也不能满足模型要求。每阶段只采用最新且已完成、结论明确的运行；进行中、中断、过期、执行错误或结论不足时，不回退到旧成功。产品、计划、套件、规则包、执行器、应用／网关、请求策略、工具和输出策略版本必须仍匹配。配置变化触发重评并使缓存成功失效；重启后从保存记录重建当前证据。

工具执行器为 `bounded-tool-tests-v1`，保存 `tool_id`／`tool_revision`，模型 `connection_id` 为空，`connection_revision` 为零。已有模型执行器及历史读取／重放格式继续支持。审计操作为 `assessment.tools.invoke`，不增加生产工具／输出计数，但仍占用全局最近 100 条索引，可能挤出旧业务样本。因此主动测试通过不能代替规则包的独立运行证据要求。

这些检查即使设置 `retain_responses: true` 也不保存工具返回正文。仅正常对照保存正文摘要／字节数。私有套件快照包含配置的资源 ID 和预期字面值；逐项回执只包含有界决策和版本，不含返回的敏感文本。备份同时保存测试记录和产品报告。重放只复算保存的规则结论，不访问工具、不重新执行检测，也不证明当前行为。报告仍是建议性的，`legal_compliance` 保持 `not_determined`。

## 本机验证

```bash
make demo-tool-assessment
```

隔离演示共 43 次本机提供方调用：两次普通正常读取、十轮五项测试，其中一轮有意扩大拒绝资源的授权。在 `dist/tool-assessment-demo/<唯一目录>/` 保存十份测试和九份报告。验证测试前为 9 通过／2 未知，两阶段通过后为 11 通过，扩大权限后出现失败，挑战缺失后恢复未知，策略变化后旧证据失效。十九份记录均须重放一致且不新增上游访问，无需外部模型或密钥。Go 测试另覆盖仅工具身份、应用撤销、审计失败、上游伪造错误、执行中配置变化、重启和非法计划。
