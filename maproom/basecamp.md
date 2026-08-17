<!-- 仅由用户决定何时更新；除非用户明确要求更新 basecamp.md，否则本文件只读，不因项目推进或内容看起来值得记录而自动改写。 -->

# vISA Basecamp

## 当前位置

vISA 当前是一套规模远大于其新职责的 WebAssembly state-continuity 研究仓库。
它拥有 portable/native state 分割、canonical reducer、runtime coordinator、
resource profile、真实 runtime/provider adapter 和多条端到端实验，但也同时保留
reference kernel、冻结 Linux service crates、重复 oracle、多个 runtime/ISA
qualification、claim/evidence publication、release scaffolding 和历史研究文档。

这些旧结果证明过若干 bounded 场景，但项目没有外部用户或兼容承诺。用户已经
决定，新实现不继承旧 API、schema、snapshot、journal、claim、evidence 或
repository-layout 义务；旧代码和文档可以直接删除，Git history 足以承担考古。

## 选定的新方向

vISA 将成为 Semantic World 的小型 portable semantic-continuation layer。它只
拥有 continuity scope、portable-state lineage、continuity profile、snapshot、
runtime safe-point 语义和 continuation recovery。

TheKernel 拥有 world、provider binding/generation、capability、native resource
和 admission/execution fence；Nexus/CSER 拥有 escaped effect、custody、outcome、
physical claim、settlement 与 retirement。vISA 通过 exact receipt 协调这些
权威，但不复制其 ledger 或自行推进其事实。

预期的最小产品面是 `visa-core`、`visa-coordinator`、`visa-profile`、
`visa-wasi` 和 `visa-reference`。这些名称表达当前责任，不构成兼容承诺。

## 可复用的基础

现有实现中值得重新审查和提取的是：

- pure preflight/apply/replay 与 rejected transition 不修改状态；
- portable logical state 与 native binding 的严格分离；
- cooperative safe point、prepare-before-activate 和失败后 source recovery；
- opaque、host-local destination preparation；
- profile-driven typed state codec 和 resource disposition；
- SQLite provider 中与真实 fencing、durability 和 fresh binding 直接相关的机制。

这些是设计和实现种子，不是必须保留的 crate、API 或依赖。Wanco 与 stock
SQLite/zstd 路径展示了 transparent compute carrier 的未来价值，但旧
qualification implementation 不作为第一条新主线保留。

## 当前约束

仓库仍固定在旧 Rust nightly，源码尚未迁移到用户更新后的工具链。因为 active
workspace 尚未收缩，现在不能把现有 build、test 或 evidence 结果视为新路线的
基线。工具链迁移应发生在破坏性删除之后，避免为即将删除的 package 和 gate
付出适配成本。

TheKernel 当前仍在收口 x86_64 Linux、io_uring 和真实 lifecycle，尚无通用
World runtime 或 vISA adapter。Nexus 也正在进行 provider-generation-aware CSER
Core rebaseline。两者不是 vISA 当前工作的阻塞依赖；vISA 先通过 reference ports
建立自己的边界，等对应外部 authority 稳定并出现真实需求后再接入。

## 面前的工作

下一阶段是 destructive rebaseline，而不是继续旧 roadmap：先删除与新核心无关
的代码、证据、脚本和文档，缩小 workspace；再迁移 Rust 工具链并重写
continuity core；随后完成两个隔离 Wasmtime Component 实例与同步 durable KV
之间的第一条 reference continuation。

当前尚未实施这些代码变化。本次只是建立新的项目规则、conceptual terrain、
用户选定 route、当前位置和已知 hazards。
