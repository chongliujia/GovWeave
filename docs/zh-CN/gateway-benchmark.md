# 合成网关负载基准

[English](../gateway-benchmark.md) | **简体中文**

GovWeave 继续使用 Go。在考虑更换语言之前，先测量实际转发与证据保存路径。`gateway-bench` 提供有边界的本机实验，覆盖直连上游对照、JSON／SSE、加密证据模式，以及独立网关进程的资源指标。它不能确定生产容量，也没有证明 Go 与 Rust 的性能差异。

## 运行

在源码目录中执行，需要 macOS 或 Linux，以及创建本机监听端口和子进程的权限：

```bash
make benchmark-gateway
```

该目标先构建不带 race detector 的普通二进制，再运行 144 组：3 轮 × 3 个并发数（`1,8,32`）× 2 个输出文本大小（`1024,16384` 字节）× JSON／SSE × 4 种模式。每组预热 16 次，正式测量 128 次。无需模型 API Key 或外部服务，所有上游请求都使用本机合成服务。

较短的可复现矩阵：

```bash
make benchmark-gateway GATEWAY_BENCH_ARGS='-requests 128 -warmup 16 -rounds 2 -concurrency 1,8 -sizes 1024,16384 -protocols json,sse'
```

JSON 与英文 Markdown 报告写入 `dist/gateway-benchmark/` 下新建的私有目录。可以用 `-out /absolute/path/to/new-directory` 指定目录；已有目录会被拒绝。每次实验前重新构建，测量时避免同时编译、运行测试或其他重负载。从其他目录运行已构建程序时，传入 `-source-root /path/to/GovWeave`。

| 参数 | 默认值 | 范围 |
| --- | --- | --- |
| `-requests` | 128 | 每组正式请求 1–512 次 |
| `-warmup` | 16 | 每组预热 1–64 次 |
| `-rounds` | 3 | 1–5 轮 |
| `-concurrency` | `1,8,32` | 不重复的整数，每项 1–128 |
| `-sizes` | `1024,16384` | 不重复的输出文本字节数，每项 128–32768 |
| `-protocols` | `json,sse` | `json`、`sse` 或两者 |
| `-provider-delay-ms` | 0 | 输出前等待 0–100 毫秒，不模拟逐 token 生成 |
| `-gomaxprocs` | min(4, 逻辑 CPU 数) | 1–128，仅影响网关子进程 |
| `-seed` | 20261031 | 控制负载／模式顺序的有符号整数 |
| `-profile` | 关闭 | `cpu`、`contention`、`trace` 或 `allocs`，最多 8 组 |

最多允许 256 组，每组限时 90 秒，客户端单次请求超时 8 秒。并发超过网关 64 请求准入上限时可能出现拒绝，错误会如实记录。大小与次数上限让每组新建证据库保持在当前对象、记录及总字节预算内；此工具不测试留存容量耗尽。

## Linux／Docker 对照

```bash
make benchmark-gateway-docker GATEWAY_BENCH_ARGS='-requests 128 -warmup 16 -rounds 2 -concurrency 8 -sizes 16384 -protocols json,sse -gomaxprocs 4'
```

构建版本默认读取生产 `Dockerfile` 的 `GO_VERSION`。首次构建需要已缓存或能下载对应官方 Go 镜像；编译使用 `GOPROXY=off` 和 `GOTOOLCHAIN=local`。`Dockerfile.benchmark` 是独立开发工具镜像，不改变生产镜像。可通过 `GATEWAY_BENCH_GO_VERSION`、`GATEWAY_BENCH_IMAGE` 显式选择对照版本和镜像名。

运行器固定为 4 CPU、1 GiB 内存（禁止额外 swap）、256 PID、非 root 用户、只读根文件系统和 `--network none`，只在容器 loopback 内通信，不映射端口。客户端、合成上游和网关子进程共用该资源限额；父进程固定 `GOMAXPROCS=4`，网关子进程值由基准参数记录。证据写入每次新建的 Docker `local` 磁盘卷，使用镜像内的源码计算哈希，不挂载宿主源码、密钥或 Docker socket，也不使用 tmpfs 模拟落盘。

只运行已构建的可信镜像，或选择单次诊断：

```bash
python3 scripts/benchmark-gateway-docker.py --image govweave-gateway-bench:local --out dist/gateway-benchmark/linux-diagnostic -- -requests 128 -warmup 16 -rounds 1 -concurrency 8 -sizes 16384 -protocols json -profile trace
```

外层私有目录保留 `docker-environment.json`（实际镜像 ID、引擎／内核、隔离配置、退出状态、其他运行容器数及清理结果）、`container.log` 和 `result/report.json`／`report.md`。运行时固定使用已检查镜像的不可变 ID。`--out` 必须是新目录；基准自身的 `-out`、`-source-root` 和 worker 入口由运行器管理，不允许覆盖。基准执行阶段超时默认 1,800 秒，随后执行有超时限制的清理；可用 `--timeout` 选择 1–21,600 秒；组内超时仍由 Go 工具控制。

正常结束或已处理的中断会先停止本次容器、复制完整／部分检查点，再删除本次 UUID 命名的容器与磁盘卷。清理失败会记录在元数据中，并以失败退出；强制杀进程或 Docker daemon 失联仍可能留下资源。运行器不会停止其他工作负载或执行全局 prune。Docker Desktop 的 Linux 虚拟机、虚拟磁盘和宿主后台负载仍影响结果，不能把它等同于裸机 Linux，也不能将其与 macOS 的差异全部归因于 Go 或单个系统调用。

可选 Docker 验收（需要先构建镜像）：

```bash
make build-gateway-bench-docker
python3 tests/gateway-bench-docker-test.py
```

验收覆盖实际隔离配置、JSON／SSE 证据回读、私有产物、路径覆盖拒绝和中断／超时后的报告与资源清理。可用 `GATEWAY_BENCH_IMAGE` 环境变量指定已构建的测试镜像。

## 运行内容

同一负载／轮次包含四组独立执行，顺序由 seed 随机化：

| 模式 | 路径 |
| --- | --- |
| `direct` | 客户端 → 合成上游 |
| `disabled` | 客户端 → 普通审计开启、内容证据关闭的网关 → 上游 |
| `metadata` | 相同网关，开启元数据证据采集 |
| `full` | 相同网关，开启加密内容证据采集 |

每组网关都使用独立进程和新的私有实例目录，运行实际的 `server.New` 路由、应用认证、连接／模型授权、网关转发、审计及证据存储代码。程序是开发测量工具，**不是分发的 `cmd/govweave` 二进制**，配置初始化与生命周期管理不同。它不会给生产服务增加诊断端点或运行参数。

应用只有一个连接，请求凭证策略使用 `observe` 模式，启用 `private_key` 和 `api_key` 两条规则。输入是固定无害文本，输出是指定长度的重复 ASCII 字符。所有网关请求声明同一个合成 trace ID，并要求上游不得收到该头。输出保护保持关闭，因为当前受保护的流式请求会被拒绝。此负载没有登记产品、安装法规包、执行工具、语义模型检测或主动测评。

上游检查请求路由、合成凭证、模型映射和内容。JSON 返回一个 completion；SSE 刷新 16 个数据帧和 `[DONE]`，不模拟逐 token 生成。客户端检查状态与完整响应字节，包括 SSE 结束标记。输出大小指文本字节数，JSON／SSE 包装额外计算，`response_bytes` 保存实际读取大小。

子进程只继承少量环境白名单，固定 `GOGC=100`、`GOMEMLIMIT=off`，并使用指定 `GOMAXPROCS`。合成凭证通过私有管道传递。父进程的上游／客户端 CPU 与堆内存不计入子进程指标，但它们仍共享同一台机器。正常结束、失败和已处理的中断都会停止子进程并移除临时实例数据。强制杀进程或机器崩溃可能遗留临时目录；不承诺安全擦除。

## 测量与证据边界

1. 完成预热，并等待预热的网关 handler 结束。
2. 获取网关资源起始快照，不强制 GC。
3. 启动固定并发客户端，保留每次正式请求的状态、错误类别、响应字节数、首个正文字节与完成时间。
4. 客户端结束后，等待网关 handler 完成，包括最终审计／采集写入，再获取资源结束快照并返回 drained 确认。
5. 在计时窗口外关闭 HTTP，回读审计和加密证据。核对成对的开始／结束记录、成功终态、精确采集数量、内容留存状态及 SSE 完整性清单。子进程退出后移除实例数据。

`client_batch_elapsed_ms` 在客户端工作完成时结束。`client_start_to_drained_ack_ms` 包含完成确认，后续核验通过才填写 `verified_successes_per_durable_second`；二者与子进程资源窗口不同。`gateway_drain_ms` 只计算收到 finish 命令后的等待，**不是**总持久化耗时。回读核验说明该时刻文件可恢复，不代表断电耐久性或完整灾难恢复验收。

单请求延迟从构造请求开始，到正文读取结束或失败为止。字节比对不计入这个计时，但客户端批次吞吐包含验证工作。直连和网关使用相同客户端。首个正文字节时间是客户端观测，并非模型首 token 时间。闭环客户端完成前一请求后才发送下一请求，无法描述独立到达率、长队列和生产饱和时的协调遗漏。

`gateway_resources` 包含进程用户态／内核态 CPU 增量、平均 CPU 核数、堆内存端点、分配量、GC 次数、暂停增量及 Go GC CPU 估计值。峰值 RSS 是**进程生命周期高水位**，包含初始化和预热，不是计时窗口内峰值。资源快照与控制消息会产生少量测量开销。Go 的 GC CPU 估计值明确不能与操作系统 CPU 直接比较，不能相除来声称 GC 占比，见官方 [runtime 指标定义](https://pkg.go.dev/runtime/metrics)。

## 阅读报告

[JSON Schema](../../schemas/gateway-benchmark.schema.json) 描述 `gateway-load-v1`。JSON 是主记录，Markdown 用于阅读。每组完成后更新两份文件；两次替换之间崩溃可能留下较旧 Markdown。已处理的中断保存 `state: failed` 和 `failed_cell`，保留之前完成的组。未完成组不放入 `results`，也不算成功。突然终止时，最后一次检查点可能仍为 `state: running`。

- `all_attempt_latency` 包含失败，`success_latency` 与 `success_first_body_latency` 仅包含成功请求。没有样本的分布为 `null`。正式请求失败与预热失败分别计数。
- 分位数采用 nearest rank。`p99_is_max_rank` 标识小样本中 P99 实际等于最大值的情况。重复合成输入不会形成独立用户样本或置信区间。
- `comparisons` 用相同轮次、协议、大小及并发数的网关分位数减去直连分位数。这是分布差值，不是逐请求配对开销；保留负值。任一客户端、上游或持久化核验失败都会抑制该比较。
- 二进制 SHA-256 标识实际程序。源码哈希标识运行开始时磁盘上的 Go 文件、内嵌资源和 `go.mod`，不证明它们与二进制对应。报告保留可获得的 VCS／构建设置及脏状态，不记录任意编译参数或环境变量。
- 退出 0 表示全部完成且功能／数量核验通过，不代表满足延迟 SLO。退出 2 表示参数无效，或全部运行完成但存在错误。退出 1 表示初始化、执行、中断或报告写入失败。

应跨轮次比较相同负载，再根据端到端延迟、CPU、GC、分配量及持久化观察选择有针对性的 profiling。高延迟、低 CPU 本身不能确定原因是磁盘、锁或调度。本工具不测量 WAN／TLS、多实例、长期内存增长、真实推理或更广泛的策略评估。语言重写需要超出本机基线的证据。

`gc_stopping` 与 `gc_total_pause` 保留计时窗口内的运行时 GC 暂停直方图差值。前者是决定暂停到所有执行线程停下来的等待时间，属于后者的子集，不能相加。报告保留非零桶、事件数和累计时长上下界（毫秒，上界不包含端点），不把桶估算成精确时长；无穷上界为 `null`，无可用差值则省略字段。事件数不是 GC 周期数。MemStats 与直方图是相邻快照，并非原子读取，不能要求逐项完全相等。

## 验证工具

### 可选性能诊断

在隔离的合成负载中，每次采集一种 profile：

```bash
make benchmark-gateway GATEWAY_BENCH_ARGS='-requests 128 -warmup 16 -rounds 1 -concurrency 8 -sizes 16384 -protocols json -profile contention'
```

将 `contention` 替换为 `cpu`、`trace` 或 `allocs`，可采集 CPU 采样、执行轨迹或分配快照。每个诊断矩阵最多 8 组。网关子进程在预热后开始采样，在结束资源快照／确认之后停止；序列化位于资源测量窗口外。contention 模式记录全部阻塞／互斥锁事件（`SetBlockProfileRate(1)`、`SetMutexProfileFraction(1)`），会增加开销。CPU 使用运行时默认采样，执行轨迹包含 GC、调度与阻塞事件。`allocs` 在测量前后分别保存运行时默认采样率下的累计分配快照，不强制 GC；采样可能滞后最多两个 GC 周期，差分还可能包含起始 profile 的序列化开销。这些模式用于**诊断，不是性能基线**；直连分位数比较会被抑制，功能／审计／证据核验仍然执行。

报告保存 `profiles/cell-NNN/` 下私有文件的相对路径、长度和 SHA-256。每个文件最多 32 MiB，超过上限会让该组失败。CPU 生成 `cpu.pprof`，contention 生成 `block.pprof` 和 `mutex.pprof`，trace 生成 `runtime.trace`，allocs 生成 `allocs-before.pprof` 与 `allocs-after.pprof`。未完成写入使用 `.partial` 名称，不列为完成产物。profile 目录为私有目录，拒绝已有内容，并随报告保留；临时网关实例数据仍会清理。栈与运行时事件可能包含源码路径和符号，但没有增加请求正文转储或自定义内容标签。显式开启 trace 时，关键审计／证据文件与目录的同步调用使用固定标签 `govweave.file_sync`，调用栈用于区分来源，标签不含路径或正文；同步语义仍是原有 `os.File.Sync`。生产服务不增加 profiling 端点。

使用报告列出的实际产物路径：

```bash
go tool pprof -top /path/to/cpu.pprof
go tool pprof -top -cum /path/to/block.pprof
go tool pprof -top -cum /path/to/mutex.pprof
go tool trace /path/to/runtime.trace
go tool pprof -top -alloc_space -base /path/to/allocs-before.pprof /path/to/allocs-after.pprof
```

block／mutex 值累加多个 goroutine 的等待时间，重叠等待可能超过墙钟耗时。mutex profile 将争用归于持锁者的 unlock 栈，block profile 展示被阻塞的调用方，不能把它们与 CPU 或墙钟时间相加，视为独立占比。短 CPU 运行可能只有少量样本。GC 暂停也可能包含运行时协调成本，不能仅凭这些文件把全部暂停归因于对象扫描。指标解释见官方 [Go 诊断指南](https://go.dev/doc/diagnostics)与 [profile 语义](https://pkg.go.dev/runtime/pprof)。

针对性改进将配置读取与证据写入分开，并把独立不可变文件的持久化移到索引锁之外，同时最多两份写入。每份捕获在等待写入名额前，先在锁内预留 ID、记录数和密文字节；仍需文件／目录同步成功后才能发布索引。不确定的失败写入保守保留容量，直到重启处理。新配置仍在授权访问日志与配置持久化成功后才可见，已经开始的请求保留冻结设置。测试覆盖独立写入推进、写入并发上限、进行中文件不可见、重复 ID、记录／字节上限、写入失败及重启恢复。审计关卡、加密和特权内容访问检查保留原有语义，见[风险证据](risk-evidence.md)。批量写入或异步持久化仍需要单独设计与验证耐久性和准入行为。


证据编码使用独立缓冲区并原地加密，避免复制整份正文及额外分配一份密文。原始 JSON／SSE 只在同步序列化期间借用，进入文件 I/O 前已形成独立密文；不会改写调用方缓冲区或将其留在索引中。nonce／密文／tag 格式兼容既有文件。测试覆盖加密不修改输入、写盘前修改源缓冲区仍不影响留存内容，以及重启读取。

### 本机调查记录（2026-11-02）

在 Go 1.25.2、macOS arm64、并发 8、输出 16 KiB 的两轮交替前后对照中，完整证据模式的分配量在 JSON 下下降约 30%，SSE 下下降约 21%–22%。32 组共 4,096 次正式请求成功，另含预热共核对 3,456 次成功网关审计、2,304 份捕获。尾延迟与持久化吞吐仍有正负变化，不能宣称稳定改善；关闭证据的对照组也有明显波动。

独立诊断中，GC 暂停直方图显示，大部分时长处于等待执行线程停下来的阶段。完整证据 trace 的 20 次 GC 暂停中，16 次包含位于 `internal/poll.(*FD).Fsync` 的抢占栈；结合本机 Go 的 Darwin `F_FULLFSYNC` 调用实现，支持同步写盘与运行时停止协调相互影响的推断。这不是独立因果证明。trace 区间还包含调度／GC 等待，不能将其全部视为磁盘耗时。

原始报告、负面结果、源码／二进制哈希及时间戳分析保存在忽略版本控制的 `dist/gateway-benchmark/2026-11-02-allocation-ab/` 和相邻诊断目录。该轮 Docker daemon 未运行，当时尚未做 Linux 或不同 Go 版本对照；本机版本也不同于 Dockerfile 的 Go 1.26.9。应在实际部署环境复测后再选择下一步持久化优化。

### Linux 对照记录（2026-11-02）

随后完成了 Docker Desktop Linux/arm64 上的两组版本对照（Go 1.25.2 和部署所用的 1.26.9），各两轮交替前后运行。64 组正式矩阵的 8,192 次请求全部成功，含预热共回读核对 6,912 次成功网关审计和 4,608 份捕获；另有 8 组独立 trace 诊断。

完整证据模式下，同为 Go 1.25.2 的优化后 Linux 组累计 GC 暂停约 1.94–2.19 ms，未复现此前 macOS 的约 219–315 ms。两个 Linux 版本的 trace 均记录到 512 个同步区间全部进入 Fsync 系统调用状态；先前 macOS trace 为 0 个。这进一步支持本机同步写盘／运行时协调的解释，但虚拟磁盘、CPU 限额和后台负载也不同，仍非单因素因果实验。

部署版本 Go 1.26.9 的四组完整证据前后比较中，分配量下降约 22%–41%，P95 下降约 11%–53%（优化后约 18 ms），持久化吞吐提升约 10%–29%。旧版本的 SSE 对照仍有回退，包括一组明显异常值；全部对照和负面结果保留在 `dist/gateway-benchmark/2026-11-02-linux-investigation/`。Go 1.26.9 的 Linux 全量 race 测试及 Docker 隔离／证据回读／清理验收通过。测量期间还有 17 个其他容器运行，这些结果不能作为生产容量或 SLA。

### 测试

```bash
make build-gateway-bench
go test -race ./internal/gatewaybench
python3 tests/gateway-bench-test.py
```

Go 测试覆盖矩阵边界／顺序、失败分母、分位数、无效比较、完整 JSON／SSE 读取、错误响应／超时、失败检查点、直方图上下界／快照隔离及有上限的 profile 发布。仅使用标准库的 Python 验收运行实际程序的 16 组普通矩阵、4 组 contention 和 4 组 allocs 诊断，核对审计／证据／资源计数、私有报告／profile 哈希及诊断比较抑制，检查拒绝覆盖和中断子进程清理。性能测量应使用不带 race 的普通构建。
