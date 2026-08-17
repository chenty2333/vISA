<!-- 仅由用户决定何时更新；除非用户明确要求更新 route.md，否则本文件只读，不因项目推进或内容看起来值得记录而自动改写。 -->

# vISA Route

vISA 将重构为 Semantic World 的 portable semantic-continuation layer。当前
仓库没有外部用户、兼容承诺或需要由新实现维持的历史证据边界；API、WIT、
schema、snapshot、journal、crate 和持久化格式都可以为更清晰的设计直接破坏。

## 1. 建立新的项目真相

以 `AGENTS.md` 和 maproom 取代旧 roadmap、claim 与 evidence 叙事，明确 vISA
只拥有 portable continuation lineage、profile、snapshot、runtime safe-point
语义和 continuation recovery。TheKernel、Nexus/CSER、runtime 与 artifact
authority 保持独立。

## 2. 破坏性收缩仓库

删除历史 claims、evidence、qualification matrices、oracles、reference kernel、
Linux service crates、旧 runtime/ISA paths、joint-handoff 产品壳层、release
readiness、publication tooling 及其文档。不创建 legacy 或 archive workspace；
需要考古时使用 Git history。

从旧实现中只提取经过重新审查且直接服务新纵向路径的思想或小段机制，随后
删除旧依赖。目标是把 active workspace 收敛到 continuity core、coordinator、
profile、WASI frontend 和 reference vertical 所需的少量 crate。

## 3. 恢复最小工具链基线

在仓库收缩后迁移到用户选定的 Rust 工具链，只修复剩余 active path 的机械
构建问题。日常 gate 保持为 format、Clippy、focused core tests 和一条真实
integration test，不重新建设旧 claim/evidence 系统。

## 4. 重写 continuity core

建立小型 `no_std` contract、portable snapshot、continuity profile vocabulary
和 pure reducer。Core 只维护 continuity scope、state lineage、合法状态转换、
profile compatibility 和 receipt requirements。

建立 restartable coordinator，但不让它拥有 TheKernel binding、capability、
native resource 或 Nexus effect outcome。Coordinator 持久化的是可恢复 intent
和收到的精确 receipt，而不是外部权威的平行 ledger。

## 5. 完成第一条 reference vertical

第一条路径使用两个隔离的 Wasmtime Component 实例、portable counter/session
state、同步 durable SQLite KV 和一个最小 reference authority/provider。

它验证 cooperative safe point、portable snapshot、equal-or-narrower
reauthorization、fresh destination binding、provider-bound source fencing、
destination restore，以及重复 prepare/commit 不产生第二个 active owner。该路径
不包含 timer、network、Nexus、TheKernel、通用 effect journal 或多 runtime
qualification。

## 6. 建立持久化恢复

让 continuation 在 source capture、destination preparation、binding commit 和
activation 周围的必要 crash cut 上可恢复。Pre-commit failure 可以恢复 source；
post-commit failure 只能恢复 destination；lost acknowledgement 必须通过真实
authority 查询得到唯一结果。

## 7. 接入 TheKernel

当 TheKernel 已有最小 `WorldId`、provider generation、generation-bound object
handle、binding publication 和 execution fence 后，通过窄 adapter 接入 vISA。
TheKernel 分配并拥有这些坐标，vISA 只携带、验证并消费 receipt。

第一条 kernel 路径是同一 x86_64 guest 中一个 provider cohort 的 `g0 -> g1`
cooperative continuation：先迁移不含 native handle 的 logical state，再增加一个
真实 regular-file/object rebind。vISA 不进入 syscall 热路径，也不从完整 Linux
process 或透明 FD migration 起步。

## 8. 按需接入 Nexus/CSER

只有当 Nexus provider-generation-aware core 已稳定，并且真实 workload 出现
跨 executor/provider lifetime 的 escaped effect 时，才接入一个 bounded CSER
profile。在此之前，vISA 遇到 unresolved escaped effect 时 fail closed。

接入后，一个 vISA logical operation 可以引用零个、一个或多个 Nexus
`EffectId`；outcome、custody、physical retirement 和 recovery-root release 仍只由
Nexus 推进。首条组合路径只覆盖一个真实 async I/O 或 logical request，不恢复
旧式 runtime × ISA × profile × fault 笛卡尔矩阵。

## 9. 由真实消费者决定扩展

三方首条组合路径成立后，再由真实需求决定是否加入第二 runtime、更多 resource
profile、transparent compute carrier、cross-host placement、semantic package 或
agent-facing action。每次扩展只增加一个新的责任或 proof obligation，不以生成
更多 schema、receipt 或 evidence bundle 作为进展。
