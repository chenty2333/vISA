<!-- 仅由用户决定何时更新；除非用户明确要求更新 terrain.md，否则本文件只读，不因项目推进或内容看起来值得记录而自动改写。 -->

# vISA Terrain

## 项目命题

vISA 是 Semantic World 架构中的 portable semantic-continuation layer。它研究并实现：
一段执行在旧 runtime、artifact 或 provider generation 中停止后，如何只携带可移植
逻辑状态与连续性要求，在新的执行环境中获得 fresh native binding，并以诚实且唯一的
后继继续执行。

Portable code 不等于 portable running state。文件描述符、socket、native pointer、
physical address、DMA state、credential、capability、runtime instance 和 provider handle
都属于具体执行环境；把它们编码成 bytes 不会使其成为可移植语义。vISA 搬运的是由
profile 解释的 logical state、resource requirements 和 lineage commitment，native
资源仍由拥有它们的真实权威重新授权和创建。

核心原则是：

> **Execution may move; semantic continuation must remain explicit.**

## 当前选择的核心模型

### Semantic domain

`SemanticDomainRef` 把一条 lineage 绑定到稳定 domain identity、contract digest 和
artifact digest。`ScopeId` 仍是 frontend 选择的连续性单位，但不再独自承担“语义闭包
已经成立”的含义；profile/frontend 必须以 domain contract 对其 closure inventory 和
capture obligation 负责。

第一条 reference vertical 采用 exact artifact compatibility，不声称已有通用 state
transform。不同 artifact 只有在真实消费者提供明确兼容关系或 transform 后才能共享
continuation domain。

### Composite source cut

`SemanticCut` 同时承诺：

```text
profile/runtime cut sequence
guest semantic safe-point digest
provider admission-closure digest
```

Runtime safe point 只证明 guest state 可以捕获，不能单独证明 provider admission、
TheKernel execution fence 或 Nexus effect closure。Reference runtime 可以在一个进程中
扮演多个测试角色，但必须保持这些事实的逻辑所有权和 receipt material 分离。

### Portable snapshot

`PortableSnapshot` 绑定：

```text
scope and semantic domain
lineage parent and canonical successor commitment
profile and state schema
source coordinate and composite semantic cut
portable logical state
resource requirements and rebind disposition
effect closure
```

Snapshot seal 和 verify 对 state、resource count、resource bytes、external coordinate、
duplicate requirement、lineage generation 和 arithmetic overflow 有明确边界。Snapshot
只声明 logical requirements，不携带 runtime/provider handle，也不授予 capability。

当前 effect contract 只接受可验证的 `Empty` closure；需要 escaped-effect continuation
的 profile 显式 fail closed。当前 reference authority 只兑现 fresh `Recreate`，其他
disposition 作为 core vocabulary 保留，但不能因为存在于 enum 中就被视为已经实现。

### State lineage

Lineage successor digest 承诺完整 canonical snapshot contract，而不是只哈希 portable
state bytes。因此改变 domain、artifact、profile、source cut、resource requirement、
disposition 或 effect closure 都会形成不同的后继。

Lineage lease 从 continuation begin 起保持排他。Commit 推进 canonical successor，但在
destination runtime activation 完成前不释放 active continuation；完整 pre-commit
rollback 则在 binding cleanup 和 source restoration 都有 exact receipt 后释放原 parent。

### Pure core 与 restartable coordination

`visa-core` 只拥有 portable contract、capture truth 和 pure validation。Core 的
`Aborted` 仅表示 capture 前的本地 intent cancellation；captured state 之后的 rollback
属于 coordinator 与外部 authority，不能用一个 receiptless core phase 冒充。

`visa-coordinator` 持久化 pending action 的 `NeverInvoked | InvokePermitted |
InvokeUnknown` 边界。Invoke 前先把 `InvokeUnknown` 写入 store；进程重启或
`Indeterminate` 后只能查询同一个 exact operation。只有首次 query 的权威 `Absent`
允许调用该 operation；已经进入 unknown 的 operation即使之后查询为 absent，也不会
直接重放旧调用，而是清除旧 pending 后重新 arm。

Pre-commit rejection 或经 exact reconciliation 证明未 commit 的操作可以进入
receipt-backed rollback。Commit 已应用或 outcome 未知时，source 永远不能被本地恢复，
后续只允许 destination-side recovery。

## 权威边界

### vISA 拥有

- portable semantic contract、snapshot 与 continuity profile identity；
- state lineage、canonical successor 和本地 active-continuation 排他；
- runtime safe-point contract 与 resource-rebinding requirements；
- coordinator intent、pending operation、verified receipt references 和 recovery requirement；
- prepared runtime 是否已经满足继续执行的本地验证条件。

### TheKernel 拥有

TheKernel 拥有 world、provider identity/generation、capability、native resource、resource
accounting、admission/operation/execution fence 和 destination binding publication。vISA
只能携带精确 opaque coordinate 并消费其 exact query/receipt，不能让本地 continuation
record 成为第二本 authority ledger。

### Nexus/CSER 拥有

Nexus/CSER 拥有 escaped effect 的 admission、identity、custody、outcome、physical claim、
settlement 和 retirement。vISA 当前没有 effect authority adapter；`Empty` 以外的 effect
closure 不是尚待优化的成功路径，而是明确不被允许的路径。

### Receipt trust

当前 receipt digest 提供 canonical material integrity，不提供密码学 issuer
authentication。第一条 vertical 的 authority 来自受信 port、exact durable operation
query 和本地 SQLite 所代表的受信边界。跨进程、跨主机或不可信 transport 若成为真实
需求，必须再绑定 issuer、deployment/replay domain 和 authenticated channel、MAC 或
signature；当前不能把公开 hash 称为这种证明。

## 当前实现形态

活动 workspace 保持一条依赖方向：

```text
visa-reference -> visa-coordinator -> visa-core
     std              no_std            no_std
```

- `visa-core`：portable contract、canonical snapshot/receipt、binding closure 和 pure reducer；
- `visa-coordinator`：restartable plan/arm/query/invoke/observe workflow、recovery 和 lineage CAS contract；
- `visa-reference`：唯一 Counter/KV profile、真实 Wasmtime Component import、SQLite store、binding authority、provider 和纵向测试。

Profile 和 Component frontend 目前是 reference-private 的具体实现，不是已经稳定的 SDK。
只有第二个真实 consumer 或 invariant 证明需要时，才提炼第二层抽象或独立 crate。

## Continuation 生命周期

当前无 escaped effects 的完整路径是：

```text
persist exact capture operation
-> close provider dispatch and reach guest safe point
-> durably seal/query portable snapshot and composite source cut
-> prepare source-bound fresh destination binding
-> prepare a fresh destination runtime instance without execution
-> authority commits source fence and durable commit receipt
-> coordinator CASes the canonical lineage successor while retaining its lease
-> restore destination state
-> authority verifies durable commit provenance and opens provider admission
-> runtime opens its local activation gate
-> release lineage lease and retire source capture
```

Reference authority/store/runtime 可以共享 SQLite 以便测试，但 fence receipt 与 lineage CAS
不是概念上的同一 authority transaction。Lost acknowledgement 必须通过 exact operation
query 恢复，不能通过另一张本地表推断。

## 明确不做

vISA 不负责：

- 透明迁移任意未修改 native process；
- 搬运 live native handle、credential 或 capability；
- 成为 kernel、runtime、provider resolver、workflow DAG 或 artifact store；
- 拥有 TheKernel binding/fence 或 Nexus effect outcome；
- 当前提供通用 effect continuity、cross-host trust、state-transform graph 或 profile registry；
- 为证明抽象性维护多 runtime/profile/target/fault 矩阵；
- 以 claim/evidence/release scaffolding 代替第一条真实 consumer path。

## 未决问题

- 第一个长期消费者需要的 scope 是单 component、provider cohort，还是 world subtree；
- profile/frontend 对 scope closure 的最小可审计义务应采用 WIT、typed schema 还是窄 receipt；
- TheKernel 的 binding/fence authority 何时具有可供 vISA exact query 的稳定 surface；
- 第一个不同 artifact 的真实 transform 是否值得进入 semantic domain contract；
- 何时出现必须 retain-old、proxy 或 reconnect，而不能 fresh recreate 的真实资源；
- Nexus/CSER 何时提供足够稳定的 effect identity、closure 和 outcome query；
- vISA 是否出现第二个非 TheKernel consumer，从而证明独立仓库和协议身份的净价值。
