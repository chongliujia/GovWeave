# 检测器插件与离线分流验证

[English](../detector-routing.md) | **简体中文**

本实验为编译注册的检测器提供统一观察结果格式，并比较三种固定的已知标记检测路径。它离线处理构造的合成文本，不安装业务响应过滤器、不调用模型，也不作法律结论。

## 运行比较

在源码仓库执行：

```bash
make validate-routing
```

也可明确指定冻结语料和回放参数：

```bash
go run ./cmd/canary-bench -routing \
  -corpus tests/testdata/canary-validation-v3.json \
  -output-dir dist/canary-routing \
  -repetitions 30 -warmup 2 -trials 2 \
  -workers 1,2 -seed 20261028 -timeout 60s
```

命令新建私有报告并打印位置，保留已有报告。比较前先检查状态：中断的实验属于未完成，已执行部分不能代表全部请求案例或轮次。取消在有界检测调用之间协作进行，无法抢占忽略 context 的插件。

观察结果契约见 [detection.schema.json](../../schemas/detection.schema.json)，比较报告见 [routing.schema.json](../../schemas/routing.schema.json)。原有[独立阶段回测](canary-benchmark.md)仍是另一个实验。

## 插件契约与边界

`internal/detection` 中的 Go 接口为：

```go
type Plugin interface {
    Descriptor() Descriptor
    Evaluate(context.Context, Input) (Finding, error)
}
```

描述符固定 `id`、`version` 和 `risk_type`。`NewRegistry` 保存描述符快照，最多接受 16 个不同 ID／版本注册项。调用必须指定准确的 ID／版本，不存在自动使用最新版的行为。注册表构造后不可变；插件实现自身仍需保持行为稳定、支持并发调用、约束工作量并配合取消。

这里的插件是随程序编译、明确注册的可信 Go 实现，不是动态 `.so` 加载、上传代码沙箱，也没有实现外部模型或分类器服务。将来的检测器除了满足接口，还需要具体实现和独立验证。

输入包含临时内容字节及可选的已知标记上下文。通用边界最多接受 8192 字节内容，要求有效 UTF-8，并将标记上下文限制为 512 字节。已知标记适配器还会执行自身更严格的标记资格检查。多个限制同时失败时，通用边界首先返回的原因可能与直接调用检测器不同。注册表先检查长度，再对限额内内容复制、计算摘要；每次调用得到独立内容副本。返回结果经过校验，插件错误使用静态错误表达，不保留插件报错原文。

观察结果记录检测器身份、风险类型、`observed`／`not_observed`／`unknown` 状态、机器可读原因、有限的字节位置证据、输入长度、耗时，以及符合相应边界时的内容摘要，不保留原始内容或标记。`evaluated` 表示是否进入过插件代码；插件失败、进入后取消或适配器返回未知时也可能为 true。证据位置指向原始输入；编码或变换区域的跨度不是解码后文本偏移。

当前注册表适配已有的精确匹配、规范化、单层和两层已知标记检测。风险类型为 `known_marker_exposure`；统一接口不会将它们自动变成通用隐私、提示注入或 AI 合规分类器。适配保持已有检测器版本、主动测试运行器和历史重放语义。

法规规则包描述证据如何支持具体技术检查及人工复核，与检测器实现分开。本轮未将新 `Observation` 格式发布为生产 `runtime.*` 或 `testing.*` 事实；已有证据路径仍以[主动测评](active-assessments.md)为准。

## 注册编译检测器

下面的仓库内最小示例实现接口，并在调用时固定版本。它只检查已知标记的字面暴露，不能替代已有适配器用于生产。

```go
// Imports: bytes, context, and govweave/internal/detection.
type literalDemo struct{}

func (literalDemo) Descriptor() detection.Descriptor {
    return detection.Descriptor{
        ID: "example_literal", Version: "example-literal-v1",
        RiskType: "known_marker_exposure",
    }
}

func (literalDemo) Evaluate(ctx context.Context, in detection.Input) (detection.Finding, error) {
    if err := ctx.Err(); err != nil {
        return detection.Finding{}, err
    }
    if in.KnownMarker == "" {
        return detection.Finding{State: detection.Unknown, Reason: "marker_required"}, nil
    }
    at := bytes.Index(in.Content, []byte(in.KnownMarker))
    if at < 0 {
        return detection.Finding{State: detection.NotObserved, Reason: "literal_not_observed"}, nil
    }
    return detection.Finding{
        State: detection.Observed, Reason: "literal_observed",
        Evidence: []detection.Evidence{{Representation: "exact", StartByte: at,
            EndByte: at + len(in.KnownMarker), SpanScope: "raw_fragment"}},
    }, nil
}

func checkDemo(ctx context.Context, in detection.Input) (detection.Observation, error) {
    registry, err := detection.NewRegistry(literalDemo{})
    if err != nil {
        return detection.Observation{}, err
    }
    return registry.Evaluate(ctx, detection.Ref{
        ID: "example_literal", Version: "example-literal-v1",
    }, in)
}
```

`observed` 结果必须附带原始内容中的证据跨度，其他状态不能携带阳性证据。接口没有概率字段；未校准的分类分数不能当作概率。法规包仍使用声明式 JSON，未来分类器或模型适配器仍需另外实现。

## 冻结的分流策略

`internal/detectionroute.FrozenManifest()` 是策略 ID、检测器引用、门控规则和版本的来源。本实验使用分流版本 `canary-routing-v1`，门控版本为 `encoded-surface-hints-v1`。

| 策略 | 执行过程 |
| --- | --- |
| `deep_reference` | 每个输入都请求固定版本的两层检测器。 |
| `normalized_fallback_all` | 先运行规范化检测。发现标记则快速返回，未知保持未知；其他情况请求两层检测器。 |
| `normalized_encoded_hint` | 使用相同快阶段。快阶段未发现后，只有内容特征命中才请求两层检测；否则最终返回 `unknown`，原因为 `deep_stage_skipped`。 |

门控只读取响应字节，不接收预期标记、标签、案例 ID、类别、分组或参考检测结论。固定特征覆盖十六进制转义、较长的 ASCII 编码字符串、十进制整数序列及编码名称。准确表达式与优先级保留在源码及 manifest 中。特征只是分流启发式，不是泄露证据或已校准的风险概率。

跳过深阶段时保留快阶段的 `not_observed` 记录，但最终路径为 `fast_only_unknown`，不能声称已检查两层范围。只有实际进入深检测插件时 `deep_evaluated` 才为 true；被通用输入边界拒绝的注册表请求不算插件执行。快阶段提前发现和快阶段未知也不执行深阶段。

这些策略仅用于离线实验。将来用于业务流量前，仍需按预期工作负载验证，并明确未知、错误和延迟限额的处理方式。

## 标签与深度参考回答不同问题

每个策略按构造标签、每个唯一样本统计一次。重复计时不增加效果样本量。泄露样本未知按漏检处理；正常样本未知不算真阴性。误报率需结合未知数量及判定覆盖率阅读。大量跳过输入的策略可能很快，同时失去判定覆盖率。

深度参考是比较器，不是真值。它自身也可能漏检、误报或返回未知，因此策略状态变化应与标签效果分开阅读：

- 丢失参考命中不一定是新增真实漏检，因为参考可能误报。
- 新增漏检要求标签为泄露、参考发现而候选未发现；候选未知也算漏检。
- 参考未知、候选未发现，不能证明不确定性得到了正确解决。
- 新增误报要求标签为正常，且候选发现而参考没有发现。

逐项路径、原因、步骤和状态迁移用于检查这些差别。与参考一致不能直接称为准确，深检测调用更少也不构成安全证据。

## 成本测量

计时单位是完整策略调用。深度基线与分流候选使用相同注册表包装，包括输入检查、内容摘要和副本、适用的快阶段、特征匹配、适用的深阶段、结果校验及流水线结果组装。为质量比较单独计算的参考结果不计入这个策略调用耗时。

旧独立阶段回测直接计时 `leakage.DetectStage`，不包含新注册表及流水线工作。因此不能将旧 P99 与新分流 P99 当作相同测量单位直接比较。

报告区分策略调用、注册表请求和插件实际进入次数，包含快／深阶段计数。策略中的 `fast_requests`／`deep_requests` 与 `fast_evaluations`／`deep_evaluations` 汇总唯一质量案例。计时轮次及负载中的 `pipeline_calls`、`registry_requests` 和快／深计数只统计完成且结果一致的调用；已尝试但失败、取消或不一致的调用另存于 `discarded_calls`，未开始的工作不计数。不计时的质量和预热调用不进入计时计数。请求成功仍可能返回未知。质量遍历已完成，不代表中断的计时实验也已完成。候选省去的深阶段只描述其自身执行计划；离线比较程序仍会执行参考及其他策略来评估该计划，不代表整次评估程序实际省去了这些调用。

单、双 worker 是本机固定并发的闭环回放，不同策略共享 CPU、内存分配及 GC 压力。调用墙钟时间含期间发生的调度与 GC，不包含排队等待，也不扣除读时钟开销。预热、参考效果计算、语料读写及报告落盘在计时区间外。批次调用速率若有展示，包含回放器工作并混合策略，不能称为模型吞吐或部署后的服务容量。

P50／P95／P99 是重复调用的经验最近秩分位数。小切片的 P99 可能选中最大值；同一文本的相关重复不能建立总体置信区间。应结合按路径、合格输入及输入大小切片解读总体混合结果。测量不含网关认证、审计 I/O、网络、模型生成和流式响应，不能建立生产实时 SLA。

## 新样本流程与证据限制

新 [v3 语料来源记录](../../tests/testdata/canary-v3-provenance.md)包含 60 个构造案例：32 个泄露、22 个非泄露和 6 个不可评估。冻结 SHA-256 为 `d0fd785f73105c898d3a8a4b47284a19465759ed1f55d525ab77468d0aa36c15`。

项目内另一代理在未查看检测实现、旧语料及结果的条件下创建并冻结新案例。首次 v3 评估前，还分别冻结了检测与分流源码摘要。评估需保留准确语料与实现身份，并统计全部冻结样本；不能根据结果删除或重标不理想案例。

这是项目内职责分离及构造标签，不是外部盲审、人工标注小组或真实模型输出验证。原有 48 例、72 例保留为开发回归数据。首次看过 v3 结果后，再调整算法就需要另一批未见数据，才能提出新的验证结论。合成标签正确性、分流保真和本机耗时分别提供不同证据，任何一项都不能单独证明通用 AI 合规。

逐案 `steps[].elapsed_ns` 来自最初的效果遍历，只作诊断记录。预热后重复调用的耗时分布应读取 `rounds` 和 `loads`；逐案数值不是额外的性能样本。

## v3 首次冻结测量

新 60 例包含 32 个泄露、22 个非泄露、6 个不可评估。首次冻结实验结果为：

| 策略 | 检出泄露 | 误报 | 未知 | 实际进入深检插件次数 |
| --- | --- | --- | --- | --- |
| 完整深度参考 | 26/32 | 0/22 | 7 | 58 |
| 规范化后全部回退 | 26/32 | 0/22 | 7 | 44 |
| 规范化后按编码特征门控 | 26/32 | 0/22 | 16 | 35 |

这些是唯一样本计数，不是计时重复次数。两个超长输入在进入插件前被拒判，因此完整深检请求为 60 次，实际进入为 58 次。全部回退在本集上保持参考结果。特征门控在本集没有新增标签漏检，但标注输入判定覆盖率从 98.15% 降到 81.48%，多出九个未知；本机实测 P99 也没有改善。只减少深检次数不能证明延迟与覆盖率的取舍有效。

另一个独立构造的单元案例包含加空格的 ROT13 文本，完整检测能发现，门控却会跳过。它证明分流存在实际失效方式，即使本次 v3 没有出现新增漏检。该门控仍属实验。完整参考自身也漏掉六个构造泄露，不能把不同语料上的百分比变化解释为能力提升。

保留的[评估前源码记录](../../tests/testdata/canary-routing-v1-freeze.json)标识首次测量前固定的检测器、注册表和分流文件；每份报告另记执行程序与 manifest 身份。看过这些结果后继续调整实现，需要新数据来支持新的验证结论。
