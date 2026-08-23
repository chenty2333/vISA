<!-- 仅由用户决定何时更新；除非用户明确要求更新 route.md，否则本文件只读，不因项目推进或内容看起来值得记录而自动改写。 -->

# vISA Route

vISA 的路线保持为一条小而完整的 semantic-continuation path。后续工作不通过增加
crate、profile、receipt 数量或产品壳层证明进展，而由真实 consumer 和尚未满足的
invariant 决定扩展。

## 1. 稳定当前三层核心

保持 `visa-core -> visa-coordinator -> visa-reference` 的单向边界：core 只保存 portable
contract 与 pure validation；coordinator 只协调 exact external facts、rollback 和
lineage；reference 只证明一条具体 Counter/KV vertical。

继续优先修复会破坏 unknown query-only、post-commit source fencing、receipt-backed
rollback、activation provenance、semantic-domain lineage 或 native-state exclusion 的
真实回归。内部 API、schema 和 crate 组织继续允许破坏，不为假想消费者建立迁移层。

## 2. 让第一个真实消费者证明 scope closure

下一次抽象应来自一个可达的 TheKernel provider-update path，而不是第二个 showcase。
该 consumer 需要明确 scope 中的 guest state、host state、logical resource、provider
admission cut 和 artifact compatibility，并证明遗漏任一可观察状态都会在 commit 前
失败。

Reference-private profile/frontend 可以被重用或拆分，但只有该 consumer 真正需要的 seam
才进入公共接口；不提前建立 profile registry、transform graph 或通用 SDK。

## 3. 接入真实 TheKernel authority

当 TheKernel 具备稳定的 provider identity/generation、generation-bound handle、binding
publication、source execution fence 和 exact operation query 后，实现一条窄 adapter。
vISA 继续只持有 opaque coordinate 和 receipt reference，不复制 world、capability、
binding 或 fence truth。

这条路径必须覆盖 source/destination 并发、lost acknowledgement、process restart 和
lineage overlap，并证明 commit-unknown 永不恢复 source、destination 首次执行使用同一
semantic cut 的 fresh binding。

## 4. 按部署边界补足 trust

当前 trusted-port/SQLite receipt model 保持明确。只有真实部署需要跨进程、跨主机或
不可信 transport 时，才加入 issuer identity、deployment/replay domain 和 authenticated
channel、MAC 或 signature。不要为尚不存在的 deployment 建 PKI 或第二套 receipt。

## 5. 等待 bounded effect authority

只有 Nexus/CSER 提供稳定的 effect identity、custody、closure 和 outcome query，并且
第一个 effectful consumer 无法用 `Empty` closure 表达时，才增加一个 bounded effect
continuity path。在此之前，非空 effect profile 一律 fail closed，不由 timeout 或本地
状态推断 retry、failure 或 settlement。

## 6. 由真实成本决定优化

性能测量只覆盖当前 control path：component preparation、fresh instance、freeze、seal、
store CAS、authority operation、restore、activation 和 recovery query。只优化已经证明的
主导成本；不得通过跳过 durability、receipt validation 或 unknown recovery 换取速度。

普通 guest/provider/syscall 热路径不属于 vISA 优化面。

## 7. 由第二个消费者决定项目边界

如果第二个性质不同的 consumer 能复用同一 semantic domain、lineage 和 recovery core，
再考虑独立 profile seam、第二 runtime 或稳定协议身份。如果真实需求都能由 TheKernel
内的专用 state machine 或普通 serialize/restart 更简单地解决，则把 vISA 作为逻辑独立
子系统吸收，而不是继续扩大独立协议。
