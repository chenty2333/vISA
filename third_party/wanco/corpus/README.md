# Wanco typed-checkpoint corpus

This directory contains focused checkpoint/restore inputs for Wanco's typed
stackmap path. The inputs are small enough to rebuild on every run; generated
LLVM, executables, and checkpoints are not retained in Git.

`typed-stackmap.wat` keeps `i32`, `i64`, `f32`, and `f64` locals live through a
six-frame direct-call chain. It also keeps one value of each type live across
the nested calls. A checkpoint at output marker `703` must therefore restore
six guest frames and four typed value-stack entries.

`typed-stackmap-indirect.wat` places two type-compatible functions in a table.
Index zero prints `999` and is deliberately wrong; index one is the long-running
checkpoint target. The caller keeps an unrelated value, the argument, and the
table selector live at `call_indirect`. A correct restore resumes index one,
restores three frames and three stack entries, and never prints `999`.

`data-segment-restore.c` is a freestanding C/Wasm workload with four nested C
functions, mixed scalar locals, address-taken linear-memory state, and a mutable
active data segment. It replaces every initialized field before the checkpoint.
Fresh-process restore must retain those mutations instead of replaying the
module's data initializer. The final checksum and the complete output stream
must match an uninterrupted control.

`post-import-root.wat` calls a host function that publishes entry marker `1003`.
For the checkpoint run, the host function first writes a nonce-bearing
`import-entered` witness and blocks. The runner verifies that nonce, successfully
dispatches `SIGUSR1` to the retained container ID, and only then atomically
publishes the matching release gate. The host function reads that gate, writes a
matching release-observed witness, publishes post-import marker `1005`, and
returns. Capture must therefore be deferred until after the hostcall returns,
while the root guest frame remains unwindable at the exact post-import stackmap.
This causal handshake guards both the signal-window placement and sibling-call
elimination of the checkpoint helper, which would otherwise remove the only
native guest frame.

Run the matrix after building the locked Wanco image:

```sh
scripts/build-wanco-carrier.sh
third_party/wanco/corpus/run-typed-checkpoint-corpus.sh
```

The runner compiles all four inputs at O0, O1, and O2. For each of the twelve
cells it compares checkpoint-prefix plus fresh-process restore output with an
uninterrupted control. It publishes a compact v4 artifact containing only the
raw control/checkpoint/restore stdout, checkpoint/restore stderr, checkpoint,
post-import witness files, locked Wanco build receipt, and a manifest. The
manifest contains no observed values, frame counts, stackmap counts, witness
summary, or verdict. Every retained file has one canonical receipt-relative
path plus its SHA-256 and size.

The standalone validator safely reopens those bytes without following symlinks
or accepting hardlink/path aliases, enforces per-file and aggregate bounds, and
then rederives the exact twelve-case inventory, output streams, frame and typed
value counts, exact stackmap records, checkpoint marker, wrong indirect-target
exclusion, and fresh-process equivalence. For the three post-import cells it
also reparses all five nonce/container/signal/release witness files. Missing,
tampered, resealed-semantic, summary-only, path-escape, alias, and relocation
mutations are covered by tests.

Run `python3 scripts/wanco_typed_corpus.py validate <root>/receipt.json` to
validate the complete retained bundle. Set `VISA_WANCO_IMAGE` to exercise a
specific local image or `VISA_WANCO_CORPUS_ROOT` to choose a new compact artifact
root; compilation products remain disposable scratch and are not copied there.

This corpus isolates compiler/runtime restore correctness. The stock SQLite
rollback-journal matrix remains the end-to-end application and WASI-provider
qualification path.
