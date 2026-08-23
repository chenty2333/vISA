<!-- 仅由用户决定何时更新；除非用户明确要求更新 basecamp.md，否则本文件只读，不因项目推进或内容看起来值得记录而自动改写。 -->

# vISA Basecamp

## 当前位置

vISA 是个人、pre-consumer 的 Semantic Continuation Engine 原型，没有生产部署、外部
用户、稳定 API 或持久化格式兼容承诺。活动 workspace 已收敛为 `visa-core`、
`visa-coordinator` 和 `visa-reference` 三个 crate；旧 profile/WASI 独立 crate、测量面、
兼容层和历史 evidence/release scaffolding 不再属于当前架构。

项目使用 rolling Rust nightly。`visa-core` 和 `visa-coordinator` 保持 `no_std + alloc`
边界，reference 使用 Wasmtime 与 SQLite 实现唯一纵向路径。当前代码应按 active
development / pre-alpha 理解，而不是发布候选。

## 已建立的核心

`visa-core` 当前拥有 semantic domain、artifact/profile commitment、composite source
cut、bounded portable snapshot、resource rebind disposition、显式 empty-effect closure、
完整 canonical lineage successor 和 pure capture reducer。Captured 后的 rollback 不再
被投影成 receiptless core abort。

`visa-coordinator` 当前持久化 exact pending operation 和 invoke boundary。Unknown 或
indeterminate outcome 只能继续 query，不能直接 reinvoke；pre-commit rollback 必须完成
binding cleanup 与 source restoration，commit 后只能进入 destination recovery。Lineage
在 commit 后继续保持 active，到 runtime activation 或完整 rollback 才释放。

`visa-reference` 的 Counter/KV vertical 使用两个隔离的 Wasmtime Component instance。
Guest 通过真实 `durable-kv-cas` import 访问 provider；binding handle 只存在于 host-local
Store state。Capture、authority operation 和 provider state 可由 SQLite exact query
恢复，destination 获得 fresh binding/provider generation，旧 source binding 在 commit
后失效。

## 当前声明边界

当前 semantic domain 采用 exact embedded artifact，没有通用 state transform。Scope
closure 由唯一 private profile/frontend 的 contract digest 和 capture obligation 背书，
不是 core 自动发现的性质。

当前 escaped-effect closure 只支持 `Empty`；reference resource 只兑现 fresh
`Recreate`。Receipt digest 是 material integrity，不是跨主机签名；reference 的 authority
来自受信 port、durable exact operation 和本地 SQLite 信任边界。

TheKernel 和 Nexus/CSER 尚未提供当前实现所需的真实 external-authority integration。
因此 vISA 目前证明的是一条同一信任域内的 cooperative Component continuation，而不是
通用迁移平台、跨主机安全协议或 effect-aware production engine。

## 最近完成的工作

最近的核心协议重构把先前只存在于设计中的 domain/cut/lineage commitment 落进了
portable contract，并修复了 unknown reinvoke、commit-unknown abort、commit/abort
互斥、activation provenance 和 lineage lease 生命周期。Reference vertical 同时从
host 旁路 KV 更新改成了 guest 的真实 Component import。

Focused core、coordinator、authority 和真实 continuation 路径已经用于保护这些关键
不变量。本项目没有为此恢复旧式矩阵、证据归档或发布设施。

## 面前的工作

近期最重要的不是继续增加 contract vocabulary，而是让当前小核心承受第一个可达的
TheKernel provider-update consumer。这个 consumer 应证明真实 scope closure、source
fence、fresh generation-bound binding、restart recovery 和唯一后继。

在出现该 consumer 前，只需要处理会破坏当前纵向路径的 focused regression、清理仍与
当前三-crate 架构不符的文档/接口表述，并保持 CI 对 format、lint、focused tests 与
no-default core/coordinator 的基本保护。Cross-host authentication、effect continuity、
第二 profile、通用 transform 和性能矩阵继续等待真实 invariant。
