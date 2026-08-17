<!-- 仅由用户决定何时更新；除非用户明确要求更新 route.md，否则本文件只读，不因项目推进或内容看起来值得记录而自动改写。 -->

# vISA Route

vISA 已建立新的 Semantic Continuation Engine 基线。下一段路线不等待 TheKernel
或 Nexus/CSER，也不提前猜测它们尚未稳定的 authority API；它继续完成 vISA 自己
能够独立证明的 durability、embedding 和 control-path efficiency。

## 1. Durable source capture

把 source capture 从一次 process-local runtime 返回值改成可恢复的 exact
operation。Coordinator 在 freeze 前持久化稳定 operation identity；runtime 或
独立 capture authority 在返回前持久化 sealed portable snapshot 和 capture
receipt；重启后的 coordinator 可以查询同一 operation，而不是依赖已经消失的
runtime token。

这一步关闭 `source frozen -> SnapshotRecorded` 之间的 dual-crash 边界。未知
capture 或 rollback 结果继续进入 `recovery-required`，不能由 timeout 或本地记录
猜成成功、失败、absent 或 aborted。

## 2. 提炼 profile 与 frontend seam

让第一条 reference vertical 证明 profile identity、typed state、resource
requirements 和 binding-grant validation 确实贯穿 capture 与 restore。逐步解除
`visa-wasi` 对 `CounterSessionState` 的硬编码，但只抽象第二个真实 state/profile
seam 所要求的部分，不建立 profile registry、transform graph 或兼容层。

WASI/Component 仍是第一套 frontend，不成为 core 的永久 ABI。Snapshot、receipt
和 profile 的具体字段、postcard 格式与 identifier 分配继续允许破坏。

## 3. 形成可嵌入的 coordinator contract

从现有 `begin`、`drive`、`recover` 和 `abort` 提炼清晰的 step outcome、pending
operation、recovery requirement 和 process-local diagnostic。外部 rejection 的原因
应能被 embedding host 观察，但不能写进 core record 并冒充 authority fact。

为 restart ownership 提供最小必要的 unfinished-continuation discovery 与查询能力，
并整理 reference-only `Rights`、coordinate、binding 和测试默认值，避免 reference
便利接口被误认为跨 TheKernel/Nexus 的稳定协议。

## 4. 测量完整 control path

围绕唯一 reference vertical 分阶段测量 component preflight/compile、fresh
instantiate、semantic freeze、portable encode/seal、record CAS、authority
prepare/commit、destination restore、activation permit 和 lost-ack recovery query。
同时记录 indeterminate 状态下的 drive/query 次数，识别紧密 polling 和锁竞争。

测量只服务当前实现决策，不重新建设 runtime、ISA、profile 和 fault 的笛卡尔矩阵，
也不产生 claim/evidence publication 系统。

## 5. 只优化已经确认的主导成本

优先考虑 adapter/scheduler 层的查询退避，以及 Wasmtime Engine、compiled
Component 和 Linker 的安全复用；每个 continuation 仍使用 fresh Store/Instance。
只有完整 record 重编码、canonical digest 或 clone 已被证明主导时，才调整 reducer
借用、编码缓冲或持久化表示。

不得通过减少 durability、跳过 receipt/snapshot 验证或把 unknown 映射成 absent 来
换取性能。普通 guest call、provider call 和 syscall 热路径不属于 vISA 优化面。

## 6. 等待真实外部 authority

TheKernel 具备稳定的 World、provider generation、generation-bound handle、binding
publication 和 execution fence 后，再实现一条窄 adapter。Nexus/CSER 具备稳定的
effect identity、outcome、custody 和 closure query 后，才加入第一个 bounded
escaped-effect profile。

在此之前，vISA 不冻结相应 wire API，不维护模拟兼容层，也不以 reference SQLite
角色替代外部系统的最终权威。

## 7. 由第一个真实消费者决定扩展

完成 durable capture、embedding seam 和测量驱动优化后，再由真实 workload
决定是否加入第二 runtime、regular-file/object rebind、更多 profile、cross-host
placement 或 bounded effect continuity。每次只增加一个真实 consumer 或 invariant，
不以增加矩阵、schema、receipt 数量或产品壳层作为进展。
