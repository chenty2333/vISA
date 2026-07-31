#!/usr/bin/env python3
"""Closed validation grammar for successful Wanco checkpoint/restore stderr."""

from __future__ import annotations

import re


class DiagnosticFailure(RuntimeError):
    """A retained Wanco process diagnostic is malformed or incomplete."""


_STACKMAP = re.compile(
    r"\[debug\] Found exact stackmap record for func_[0-9]+, "
    r"wasm_op=-?[0-9]+, native_return_pc_offset=0x[0-9a-f]+"
)
_RATIO = re.compile(r"\[info\] Compression ratio: [0-9]+(?:\.[0-9]+)?")
_MILLISECONDS = re.compile(r"\[info\] Compression time: [0-9]+ ms")
_DECOMPRESS = re.compile(
    r"\[info\] Decompressing memory: ([1-9][0-9]*) pages "
    r"\(([1-9][0-9]*) bytes\)"
)
_CALL_STACK = re.compile(r"\[info\] - call stack: ([1-9][0-9]*) frames")
_VALUE_STACK = re.compile(r"\[info\] - value stack: ([0-9]+) values")


def _lines(payload: bytes, label: str) -> list[str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise DiagnosticFailure(f"{label} is not UTF-8") from error
    if text and not text.endswith("\n"):
        raise DiagnosticFailure(f"{label} lacks its final newline")
    return text.splitlines()


def validate_checkpoint_stderr(payload: bytes, label: str) -> dict[str, int]:
    lines = _lines(payload, label)
    if len(lines) < 7 or lines[0] != "[info] Checkpoint started":
        raise DiagnosticFailure(f"{label} lacks the checkpoint start terminal")
    stackmaps = lines[1:-5]
    if not stackmaps or any(_STACKMAP.fullmatch(line) is None for line in stackmaps):
        raise DiagnosticFailure(f"{label} has an invalid exact-stackmap sequence")
    tail = lines[-5:]
    if (
        tail[0] != "[info] Compressing memory"
        or _RATIO.fullmatch(tail[1]) is None
        or _MILLISECONDS.fullmatch(tail[2]) is None
        or tail[3] != "[info] Snapshot has been saved to checkpoint.pb"
        or tail[4] != "[info] Checkpoint time has been saved to chkpt-time.txt"
    ):
        raise DiagnosticFailure(f"{label} lacks the checkpoint success terminals")
    return {"exact_stackmap_records": len(stackmaps)}


def validate_restore_stderr(payload: bytes, label: str) -> dict[str, int]:
    lines = _lines(payload, label)
    if len(lines) != 5:
        raise DiagnosticFailure(f"{label} has extra or missing restore diagnostics")
    decompression = _DECOMPRESS.fullmatch(lines[0])
    if decompression is None:
        raise DiagnosticFailure(f"{label} lacks the decompression terminal")
    pages, byte_count = (int(value) for value in decompression.groups())
    if byte_count != pages * 65536:
        raise DiagnosticFailure(f"{label} has an inconsistent restored memory size")
    if (
        lines[1] != "[info] Checkpoint has been loaded"
        or _CALL_STACK.fullmatch(lines[2]) is None
        or _VALUE_STACK.fullmatch(lines[3]) is None
        or lines[4] != "[info] Restore time has been saved to restore-time.txt"
    ):
        raise DiagnosticFailure(f"{label} lacks the restore success terminals")
    call_stack = _CALL_STACK.fullmatch(lines[2])
    value_stack = _VALUE_STACK.fullmatch(lines[3])
    assert call_stack is not None and value_stack is not None
    return {
        "memory_pages": pages,
        "memory_bytes": byte_count,
        "restored_frames": int(call_stack.group(1), 10),
        "restored_values": int(value_stack.group(1), 10),
    }


def validate_checkpoint_restore_pair(
    checkpoint_payload: bytes,
    restore_payload: bytes,
    label: str,
) -> tuple[dict[str, int], dict[str, int]]:
    checkpoint = validate_checkpoint_stderr(
        checkpoint_payload, f"{label} checkpoint stderr"
    )
    restore = validate_restore_stderr(restore_payload, f"{label} restore stderr")
    if checkpoint["exact_stackmap_records"] != restore["restored_frames"]:
        raise DiagnosticFailure(
            f"{label} exact stackmap count differs from the restored frame count"
        )
    return checkpoint, restore


def validate_application_stderr(
    role: str, payload: bytes, label: str
) -> dict[str, int]:
    if role == "source":
        return validate_checkpoint_stderr(payload, label)
    elif role == "destination":
        return validate_restore_stderr(payload, label)
    elif role in {"control", "transaction", "cursor", "transaction-setup", "readback"}:
        if payload:
            raise DiagnosticFailure(f"{label} must be empty")
        return {}
    else:
        raise DiagnosticFailure(f"{label} has an unsupported application role {role!r}")
