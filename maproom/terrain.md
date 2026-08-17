<!-- 仅由用户决定何时更新；除非用户明确要求更新 terrain.md，否则本文件只读，不因项目推进或内容看起来值得记录而自动改写。 -->

# vISA Terrain

## 项目命题

vISA 研究并实现 **portable semantic continuation**：一段执行在旧
runtime、world 或 provider generation 中停止后，如何只携带可移植的逻辑
状态和连续性要求，在新的执行环境中重新获得权限、重建 native binding，
然后以诚实且唯一的后继状态继续执行。

Portable code 不是 portable running state。文件描述符、socket、native
pointer、physical address、DMA descriptor、credential、capability object 和
runtime-private handle 都属于具体实现，不能因为被序列化就变成可移植语义。
vISA 搬运的是应用和 semantic provider 已经承诺的逻辑状态与恢复要求；具体
资源必须由目的端的真实权威重新授权、重新创建、重新连接、重新附着、代理，
或者显式拒绝。

vISA 的核心原则是：

> **Execution may move; semantic continuation must remain explicit.**

## 最终形态

vISA 最终是一套小型、可嵌入的 **Semantic Continuation Engine**，而不是
独立操作系统、通用 runtime、迁移平台大全或拥有全局真相的 daemon。它由
portable contract、pure reducer、restartable coordinator、profile SDK 和
少量 frontend/adapter 组成。

TheKernel 是最终系统和用户入口。TheKernel 的 world manager、runtime 或
provider-update control path 在需要 freeze、move、restore 或 rebind 时调用
vISA；正常 syscall、provider call 和应用热路径不经过 vISA。WASI/Component
是第一套 frontend，但不构成 core 的永久边界。

## 权威边界

### vISA 拥有的事实

vISA 是 portable continuation lineage 的唯一权威。它拥有：

- `ContinuityScopeId`：本次连续性操作覆盖的明确 component、component
  group、provider cohort 或其他执行单元；
- `StateLineageId` 与 state generation：portable state 的合法前驱和后继；
- `ContinuityProfile`：portable-state schema、resource requirements、
  compatibility、rebind disposition 和 logical recovery semantics；
- `PortableSnapshot`：绑定 scope、lineage、profile、source semantic cut、
  portable state 和逻辑资源要求的规范封装；
- runtime semantic safe point，以及准备好的 continuation 是否满足恢复条件；
- `ContinuationRecord`：可恢复的协调 intent、收到的外部 receipt 引用和
  `preparing | frozen | destination-prepared | committed | aborted |
  recovery-required | activated` 等本地连续性状态。

vISA 可以判断 snapshot 是否属于某条合法 lineage、目标 profile 是否能够
解释它、需要重建哪些逻辑资源，以及当前 receipt 集是否足以让 runtime
继续。它不能用本地记录制造其他权威拥有的事实。

### TheKernel 拥有的事实

TheKernel 拥有 `WorldId`、provider identity/generation、native object、
capability、resource accounting、semantic-provider graph、Default/Object/
Settlement binding，以及 admission、operation 和 execution fence。它创建
目标 native binding，并权威发布 source fence 与 destination binding。

vISA 只携带这些 identity 的精确 opaque coordinate，声明所需权限，并验证
TheKernel 返回的 receipt。Snapshot 不授予 capability，恢复只能获得目标
权威实际签发的相等或更窄权限。

### Nexus/CSER 拥有的事实

Nexus/CSER 拥有已经逃逸出 executor/provider lifetime 的 effect：effect
admission、identity、custody、logical outcome、physical claim、settlement、
retirement 和 effect-driven recovery-root release。

一次 vISA logical operation 可以对应零个、一个或多个 CSER effect。vISA
可以保存 `EffectId` 和经过验证的 status/closure receipt，并把 CSER 已确定的
结果投影成应用可见的 logical recovery state；它不能自行把 `pending` 或
`indeterminate` 改成 failed、completed 或 replayable，也不能因为 destination
已经恢复就释放旧 physical claim 或 artifact。

### 其他系统拥有的事实

runtime 或 compute carrier 捕获和恢复实际执行状态；artifact authority/Nix
负责 artifact realization、持久化和 GC；resolver 选择 provider graph；远程
trust、TEE/KMS 和 workflow 系统拥有各自协议。vISA 只消费必要的精确结果，
不吸收这些系统。

## 核心模型

### Continuity scope

连续性单位由显式 `ContinuityScope` 定义，不预设为整台机器、整个进程或整个
World。scope 必须能够说明 portable state、logical resources、source cut
以及目标恢复所需的语义闭包。实际粒度由第一个真实消费者验证，而不是由通用
抽象提前锁死。

### Continuity profile

`ContinuityProfile` 是完整 semantic contract 的连续性投影，而不是新的操作
系统 personality。它描述：

```text
portable state schema
resource requirements
required rights
compatibility and state transform
rebind disposition
logical recovery semantics
```

资源可以选择 `recreate`、`reconnect`、`reattach`、`proxy`、
`replay-if-authorized`、`retain-old` 或 `reject`。Profile 必须允许不可安全重建
的资源明确失败；它不承诺所有资源都能透明迁移。

### Portable snapshot

Portable snapshot 是 committed portable truth 的规范投影，不是进程内存、
provider 数据库或 native resource table 的 dump。它至少绑定：

```text
scope and state lineage
profile and state schema
portable logical bytes
logical resource requirements
source semantic cut
optional external effect references
```

runtime preparation、native binding 和 capability token 都是 opaque、host-local
且不可序列化的对象。Snapshot、view、receipt 和 observation 都不能成为平行
ledger。

## Continuation 生命周期

一个完整 continuation 具有如下因果关系：

```text
select scope and target
-> prepare destination artifacts/runtime/provider without execution
-> close source admission and, when needed, escaped-effect admission
-> reach a runtime semantic safe point
-> seal portable snapshot and source cut
-> settle, retain, reconcile, or reject unresolved effects
-> reauthorize and prepare fresh destination bindings
-> TheKernel commits source fence and destination binding
-> vISA validates the exact receipts and restores runtime state
-> old effects and artifacts retire under their own authorities
```

允许 destination preparation 与 source quiescence 在不执行目标 workload 的前提
下重排，但 activation 的前置关系不能改变：没有真实 source fence、目标 binding
和 profile 所要求的 effect closure，就不能开始目标执行。

Pre-commit 失败可以清理目标并恢复 source。Commit 后失败不能复活 source；
它进入 destination recovery。缺失、冲突或无法验证的外部事实进入
`recovery-required`，不能由 timeout、进程死亡、日志缺失或本地猜测变成 abort、
success 或 retry authority。

## 实现边界

预期的逻辑产品面是：

```text
visa-core
  no_std contract、portable snapshot、profile vocabulary、pure reducer

visa-coordinator
  restartable continuity workflow、receipt validation、recovery decisions

visa-profile
  profile SDK、typed portable-state codec、rebind/recovery hooks

visa-wasi
  第一套 WASI/Component frontend 和 cooperative safe-point adapter

visa-reference
  最小 host authority/provider、真实 runtime 和端到端测试
```

这些名称是当前清晰的责任边界，不是需要永久保持的 crate ABI。TheKernel 和
Nexus integration 应位于各自仓库或独立 adapter 中；vISA core 不反向依赖
内核或 effect authority。

## 明确不做

vISA 不负责：

- 透明迁移任意未修改 native process；
- 序列化或转移任意 live native handle；
- WebAssembly engine、kernel、filesystem、network stack 或 device model；
- world/provider resolver、plugin loader、workflow DAG 或 artifact store；
- escaped-effect custody、physical retirement 或通用 exactly-once；
- 全局 ownership、capability 签发或 native binding publication；
- TEE、KMS、remote trust 或 confidential-computing platform；
- 为证明抽象性而维护 runtime、ISA、profile 和 fault 的笛卡尔矩阵；
- 以 claim registry、evidence archive 或 publication pipeline 代替当前实现。

## 未决问题

- 第一个长期有价值的 `ContinuityScope` 是单 component、component group、
  provider cohort，还是一个 world subtree；
- `ContinuityProfile` 最终使用 WIT extension、独立 canonical schema，还是二者
  组合；
- 哪些 application-visible operation 状态属于 portable continuation，哪些只
  是 CSER outcome 的投影；
- TheKernel binding commit 与 vISA lineage commit 通过 in-process token、durable
  receipt 还是其他协议连接；
- 何种资源必须 retain-old，何种资源可以 rebind，何种资源必须显式拒绝；
- vISA 最终保留独立仓库/协议身份，还是作为 TheKernel 子系统吸收。无论代码
  归属如何，权威边界不改变。
