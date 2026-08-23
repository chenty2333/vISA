# vISA Hazards

本文件只记录已经由现有设计和实现经历确认、且容易在 vISA 重构中重复出现的
项目特定陷阱。它不是状态报告、路线图、结果账本或通用编码指南。

## Semantic safe point 不是完整 source fence

Component/runtime 到达 cooperative safe point，只能说明 portable state 可以在
该语义边界捕获。它不自动关闭 TheKernel admission/operation/execution authority，
也不证明 Nexus escaped effect 已经 settle 或 physical resource 已经静默。把这些
事实压成一个 `frozen` 状态会允许 source 或旧 provider 在 destination 启动后
继续产生工作。

## Process-local capture 不是 durable snapshot

Runtime 停止 source、关闭 provider dispatch 并返回 sealed snapshot，只能证明当前
进程曾形成该 semantic cut；在 coordinator 原子记录 `SnapshotRecorded` 或 durable
capture authority 返回可查询 receipt 之前，重启后的进程仍无法取得这份 snapshot。
若在该窗口同时丢失 coordinator 和 source runtime，不能从 lineage parent 重放、
重新打开 source，或把缺失 snapshot 猜成 aborted。Rollback acknowledgement 和
snapshot-store acknowledgement 同样可能丢失，必须查询精确 operation 或保留
`recovery-required`。

## Continuation record 和 receipt 不是外部 authority

vISA 可以保存协调 intent、receipt 和查询结果，但不能因为本地记录了
`committed` 就推进 TheKernel binding、Nexus outcome、physical retirement 或
artifact release。Crash recovery 必须重新验证真正权威的精确状态；projection、
缓存、文件存在或缺失 acknowledgement 都不能替代它。

## Portable snapshot 不携带 native state 或 authority

fd、socket、native pointer、PFN/paddr、DMA/queue descriptor、credential、
capability 和 runtime/provider handle 即使能够编码，也不是 portable semantic
state。Snapshot 只能声明 logical resource requirement；目的端必须重新授权并
创建 fresh binding。接受 snapshot 本身作为权限会放大或复活 source authority。

## Post-commit failure 不能复活 source

Pre-commit cleanup 可以恢复 source，但 TheKernel 一旦权威提交 source fence 和
destination binding，后续 destination preparation、runtime restore 或 transport
失败都属于 destination recovery。把它改写成 abort 并 thaw source 会形成两个
可能的后继。

## Unknown external outcome 不是失败或 retry authority

Timeout、进程死亡、transport unavailable、日志缺失和 polling exhaustion 都不能
证明一个 escaped effect 未发生。没有 Nexus/provider 的权威结果时，vISA 必须
保留 `recovery-required` 或拒绝继续，不能自行映射成 failure、cancelled、absent
或 replayable。

实现上必须先持久化 invoke boundary。进入 `InvokeUnknown` 后只能查询同一个 exact
operation，不能保留可直接执行的 invoke permission。即使后续 exact query 明确返回
`Absent`，也应结束旧 pending 并重新 arm，而不是把曾经 outcome unknown 的旧调用原样
重放。

## Captured core abort 不能替代 receipt-backed rollback

Capture 前的本地 intent cancellation 可以是 pure core event；一旦 snapshot 已经由 exact
receipt 记录，binding cleanup 和 source restoration 都属于各自 authority。把 captured
record 直接改成 `Aborted` 会丢失 pending operation，甚至在 source 已冻结或 commit
outcome unknown 时错误恢复 source。Captured rollback 必须由 coordinator 保存明确状态，
并在 cleanup/restoration receipt 完整后才成为 terminal。

## Lineage successor 必须承诺完整 semantic contract

只把 portable state bytes 的 digest 写入 lineage head，会让 profile、artifact、source
cut、resource requirement、rebind disposition 或 effect closure 不同的 snapshot 被视为
同一语义后继。Canonical successor 必须覆盖完整 snapshot contract，并在 commit 后继续
保持 active lease，直到 destination activation 或完整 rollback；commit 时立即释放会允许
重叠后继。

## Reference all-in-one host 不能合并逻辑权威

第一条 reference vertical 可以在一个进程或 SQLite database 中实现多个测试
角色，但 contract、trait 和状态所有权仍必须分开表达 runtime、continuation、
binding authority 和 resource provider。部署方便不能成为把它们重新合并为一本
canonical journal 的理由。

## 历史验证基础设施不能决定 active architecture

旧 claim registry、source locks、evidence schemas、matrix verifiers、publication
scripts 和 release checkers 曾把大量无运行时价值的路径固定在 workspace 与 CI
中。新实现删除或重写旧语义时，不得为了让这些历史 gate 继续通过而保留旧
crate、兼容 shim、平行模型或文档；需要过去信息时使用 Git history。
