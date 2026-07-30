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

Run the matrix after building the locked Wanco image:

```sh
scripts/build-wanco-carrier.sh
third_party/wanco/corpus/run-typed-checkpoint-corpus.sh
```

The runner compiles all three inputs at O0, O1, and O2. For each of the nine cells it
compares checkpoint-prefix plus fresh-process restore output with an
uninterrupted control. Set `VISA_WANCO_IMAGE` to exercise a specific local image
or `VISA_WANCO_CORPUS_ROOT` to retain results at an explicit new path.

This corpus isolates compiler/runtime restore correctness. The stock SQLite
rollback-journal matrix remains the end-to-end application and WASI-provider
qualification path.
