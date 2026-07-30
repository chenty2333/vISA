#!/usr/bin/env python3
"""Focused tests for retained Wanco process diagnostics."""

from __future__ import annotations

import unittest

import wanco_process_diagnostics as DIAGNOSTICS


CHECKPOINT = (
    b"[info] Checkpoint started\n"
    b"[debug] Found exact stackmap record for func_19, wasm_op=-1, "
    b"native_return_pc_offset=0x2a\n"
    b"[info] Compressing memory\n"
    b"[info] Compression ratio: 0.275372\n"
    b"[info] Compression time: 1 ms\n"
    b"[info] Snapshot has been saved to checkpoint.pb\n"
    b"[info] Checkpoint time has been saved to chkpt-time.txt\n"
)
RESTORE = (
    b"[info] Decompressing memory: 5 pages (327680 bytes)\n"
    b"[info] Checkpoint has been loaded\n"
    b"[info] - call stack: 21 frames\n"
    b"[info] - value stack: 0 values\n"
    b"[info] Restore time has been saved to restore-time.txt\n"
)


class DiagnosticTests(unittest.TestCase):
    def test_success_grammars_are_accepted(self) -> None:
        DIAGNOSTICS.validate_application_stderr("source", CHECKPOINT, "source")
        DIAGNOSTICS.validate_application_stderr("destination", RESTORE, "destination")
        DIAGNOSTICS.validate_application_stderr("control", b"", "control")

    def test_extra_error_and_missing_terminals_are_rejected(self) -> None:
        for role, payload in (
            ("source", CHECKPOINT + b"fatal: forged\n"),
            ("source", CHECKPOINT.replace(b"Checkpoint started\n", b"")),
            ("destination", RESTORE + b"Error: segmentation fault\n"),
            ("destination", RESTORE.replace(b"Checkpoint has been loaded\n", b"")),
            ("readback", b"unexpected\n"),
        ):
            with self.subTest(role=role), self.assertRaises(
                DIAGNOSTICS.DiagnosticFailure
            ):
                DIAGNOSTICS.validate_application_stderr(role, payload, role)

    def test_restore_memory_size_and_encoding_are_checked(self) -> None:
        with self.assertRaises(DIAGNOSTICS.DiagnosticFailure):
            DIAGNOSTICS.validate_restore_stderr(
                RESTORE.replace(b"327680", b"327681"), "destination"
            )
        with self.assertRaises(DIAGNOSTICS.DiagnosticFailure):
            DIAGNOSTICS.validate_checkpoint_stderr(b"\xff", "source")


if __name__ == "__main__":
    unittest.main()
