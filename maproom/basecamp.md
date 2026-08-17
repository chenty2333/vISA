<!-- 仅由用户决定何时更新；除非用户明确要求更新 basecamp.md，否则本文件只读，不因项目推进或内容看起来值得记录而自动改写。 -->

# vISA Basecamp

## 当前位置

vISA 已完成 destructive rebaseline，当前是一套小型、可嵌入、可恢复的
Semantic Continuation Engine，而不是旧 WebAssembly continuity 研究仓库的兼容
演进。Active workspace 已收敛为 `visa-core`、`visa-coordinator`、
`visa-profile`、`visa-wasi` 和 `visa-reference` 五个 crate；旧 reference kernel、
Linux service、runtime/ISA qualification、oracle、claim/evidence、publication 和
release scaffolding 已从活动树删除，历史只由 Git 保留。

项目已迁移到 Rust 1.95。当前核心、profile 和 reducer 保持 `no_std + alloc`
边界，完整 workspace 通过格式、严格 lint、测试和无默认特性检查。这些检查保护
当前实现，不构成稳定 API、持久化格式或兼容承诺。

## 已建立的引擎

`visa-core` 已拥有 portable snapshot、continuity scope、state lineage、profile
identity、resource requirement、canonical receipt 和 pure preflight/apply reducer。
`visa-coordinator` 已实现 durable pending operation、exact lost-ack query、原子
lineage CAS，以及 pre-commit source recovery 与 post-commit destination recovery
的分离。

第一条 reference vertical 使用两个隔离的 Wasmtime Component instance、typed
counter/session state、SQLite continuation store、reference binding authority 和
durable KV provider。它已经验证 fresh destination binding、provider generation
推进、source fencing、双重 activation gate、重复调用幂等，以及 prepare、commit
和 activation acknowledgement 丢失后的重启恢复。Portable snapshot 不包含
runtime instance、SQLite connection、provider handle、capability 或其他 native
state。

## 当前真实边界

Durable recovery 从 sealed snapshot 被原子记录为 `SnapshotRecorded` 开始。在
runtime 已停止 source 并形成 process-local snapshot、但 coordinator 尚未把该
snapshot 持久化的窗口内，如果 coordinator 和 source runtime 同时消失，新进程
没有足够事实重建 guest state。当前实现对此进入 `recovery-required`，不会猜测
abort、success 或重新打开 source。

TheKernel 和 Nexus/CSER 目前都尚未形成适合 vISA 消费的稳定 authority surface。
这不阻塞 vISA 自身继续演进，但意味着现在不应冻结 `WorldId`、binding receipt、
effect closure 或跨仓库 wire API。Unresolved escaped effects 继续 fail closed。

## 面前的工作

下一阶段首先把 source capture 变成可查询的 durable operation，关闭
pre-snapshot dual-crash 边界。随后从现有 reference vertical 中提炼真正可嵌入的
profile/WASI seam 和 coordinator step/diagnostic API，但继续允许内部 API、schema
和持久化格式破坏。

性能工作采用 measurement-first：分别观察 component preflight、fresh instance、
freeze、snapshot seal、record CAS、authority prepare/commit、restore、activation 和
recovery query 的成本，再只优化确认主导的 Wasmtime、SQLite、polling 或编码路径。
vISA 不进入普通 syscall、provider call 或应用热路径，也不恢复旧式 benchmark
矩阵。
