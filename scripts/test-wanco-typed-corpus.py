#!/usr/bin/env python3
"""Raw-artifact and adversarial mutation tests for Wanco typed restore."""

from __future__ import annotations

import copy
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

import wanco_typed_corpus as CORPUS


IMAGE_TAG = "visa-wanco-carrier:locked"
IMAGE_ID = "sha256:" + "ab" * 32


def _varint(value: int) -> bytes:
    if value < 0:
        value &= (1 << 64) - 1
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _field_varint(field: int, value: int) -> bytes:
    return _varint(field << 3) + _varint(value)


def _field_bytes(field: int, value: bytes) -> bytes:
    return _varint((field << 3) | 2) + _varint(len(value)) + value


def _value(value_type: str) -> bytes:
    number = {"i32": 1, "i64": 2, "f32": 3, "f64": 4}[value_type]
    payload = _field_varint(1, number)
    if value_type == "i32":
        return payload + _field_varint(2, 7)
    if value_type == "i64":
        return payload + _field_varint(3, 11)
    if value_type == "f32":
        return payload + _varint((4 << 3) | 5) + struct.pack("<f", 1.25)
    return payload + _varint((5 << 3) | 1) + struct.pack("<d", 2.5)


def lz4_literal_block(payload: bytes) -> bytes:
    encoded = bytearray()
    literal_length = len(payload)
    encoded.append(min(literal_length, 15) << 4)
    if literal_length >= 15:
        remainder = literal_length - 15
        while remainder >= 255:
            encoded.append(255)
            remainder -= 255
        encoded.append(remainder)
    encoded.extend(payload)
    return bytes(encoded)


def lz4_terminal_match_block(output_size: int) -> bytes:
    match_length = output_size - 1
    encoded = bytearray((0x1F, ord("A"), 0x01, 0x00))
    remainder = match_length - 4 - 15
    while remainder >= 255:
        encoded.append(255)
        remainder -= 255
    encoded.append(remainder)
    return bytes(encoded)


def lz4_late_match_block(output_size: int) -> bytes:
    initial_literals = output_size - 9
    encoded = bytearray((0xF0,))
    remainder = initial_literals - 15
    while remainder >= 255:
        encoded.append(255)
        remainder -= 255
    encoded.append(remainder)
    encoded.extend(b"A" * initial_literals)
    encoded.extend((0x01, 0x00))
    encoded.extend((0x50,))
    encoded.extend(b"B" * 5)
    return bytes(encoded)


def checkpoint_payload(
    spec: CORPUS.CaseSpec, *, compressed_memory: bytes | None = None
) -> bytes:
    payload = bytearray()
    for frame_index in range(spec.frames):
        frame = bytearray()
        frame += _field_varint(1, frame_index + 1)
        frame += _field_varint(2, frame_index + 17)
        if frame_index == 0:
            for value_type in spec.required_local_types:
                frame += _field_bytes(3, _value(value_type))
            for value_type in spec.expected_stack_types:
                frame += _field_bytes(4, _value(value_type))
        payload += _field_bytes(1, bytes(frame))
    payload += _field_bytes(2, _value("i32"))
    payload += _field_bytes(3, _varint(0))
    memory_pages = 2 if spec.profile == "data-segment" else 1
    payload += _field_varint(4, memory_pages)
    if compressed_memory is None:
        compressed_memory = lz4_literal_block(b"\0" * (memory_pages * 65536))
    payload += _field_bytes(5, compressed_memory)
    return bytes(payload)


def checkpoint_payload_with_omitted_frame_defaults(
    spec: CORPUS.CaseSpec,
) -> bytes:
    payload = bytearray()
    for frame_index in range(spec.frames):
        frame = bytearray()
        if frame_index != 0:
            frame += _field_varint(1, frame_index)
            frame += _field_varint(2, frame_index)
        if frame_index == 0:
            for value_type in spec.required_local_types:
                frame += _field_bytes(3, _value(value_type))
            for value_type in spec.expected_stack_types:
                frame += _field_bytes(4, _value(value_type))
        payload += _field_bytes(1, bytes(frame))
    payload += _field_bytes(2, _value("i32"))
    payload += _field_bytes(3, _varint(0))
    memory_pages = 2 if spec.profile == "data-segment" else 1
    payload += _field_varint(4, memory_pages)
    payload += _field_bytes(
        5, lz4_literal_block(b"\0" * (memory_pages * 65536))
    )
    return bytes(payload)


def llvm_stackmap_payload(spec: CORPUS.CaseSpec) -> bytes:
    type_codes = {"i32": 0, "i64": 1, "f32": 2, "f64": 3}
    type_sizes = {"i32": 4, "i64": 8, "f32": 4, "f64": 8}
    records: list[tuple[int, tuple[str, ...], tuple[str, ...]]] = []
    for frame_index in range(spec.frames):
        local_types = spec.required_local_types if frame_index == 0 else ()
        stack_types = spec.expected_stack_types if frame_index == 0 else ()
        patchpoint_id = ((frame_index + 1) << 32) | (frame_index + 17)
        records.append((patchpoint_id, local_types, stack_types))

    payload = bytearray(
        struct.pack("<BBHIII", 3, 0, 0, len(records), 0, len(records))
    )
    for function_index in range(len(records)):
        payload += struct.pack(
            "<QQQ",
            0x401000 + function_index * 0x100,
            0x80,
            1,
        )

    def location(kind: int, size: int, register: int, value: int) -> bytes:
        return struct.pack("<BBHHHi", kind, 0, size, register, 0, value)

    for patchpoint_id, local_types, stack_types in records:
        locations = [
            location(4, 4, 0, CORPUS.STACKMAP_LAYOUT_V2),
            location(4, 4, 0, len(local_types)),
            location(4, 4, 0, len(stack_types)),
        ]
        for value_index, value_type in enumerate((*local_types, *stack_types)):
            locations.extend(
                (
                    location(4, 4, 0, type_codes[value_type]),
                    location(
                        3,
                        type_sizes[value_type],
                        6,
                        -8 * (value_index + 1),
                    ),
                )
            )
        payload += struct.pack("<QIHH", patchpoint_id, 0x20, 0, len(locations))
        payload += b"".join(locations)
        if len(payload) % 8:
            payload += b"\0" * (8 - len(payload) % 8)
        payload += struct.pack("<HH", 0, 0)
        if len(payload) % 8:
            payload += b"\0" * (8 - len(payload) % 8)
    return bytes(payload)


def aot_elf_payload(spec: CORPUS.CaseSpec) -> bytes:
    section_names = b"\0.shstrtab\0.llvm_stackmaps\0"
    stackmap = llvm_stackmap_payload(spec)
    string_offset = 64
    stackmap_offset = (string_offset + len(section_names) + 7) & ~7
    section_table_offset = (stackmap_offset + len(stackmap) + 7) & ~7

    ident = b"\x7fELF\x02\x01\x01\x03" + b"\0" * 8
    payload = bytearray(
        struct.pack(
            "<16sHHIQQQIHHHHHH",
            ident,
            2,
            62,
            1,
            0,
            0,
            section_table_offset,
            0,
            64,
            0,
            0,
            64,
            3,
            1,
        )
    )
    payload += section_names
    payload += b"\0" * (stackmap_offset - len(payload))
    payload += stackmap
    payload += b"\0" * (section_table_offset - len(payload))
    payload += bytes(64)
    payload += struct.pack(
        "<IIQQQQIIQQ",
        1,
        3,
        0,
        0,
        string_offset,
        len(section_names),
        0,
        0,
        1,
        0,
    )
    payload += struct.pack(
        "<IIQQQQIIQQ",
        len(b"\0.shstrtab\0"),
        1,
        2,
        0,
        stackmap_offset,
        len(stackmap),
        0,
        0,
        8,
        0,
    )
    return bytes(payload)


def case_streams(spec: CORPUS.CaseSpec) -> tuple[list[int], list[int], list[int]]:
    control = list(spec.expected_control)
    marker_index = control.index(spec.marker)
    return control, control[: marker_index + 1], control[marker_index + 1 :]


def write_values(path: Path, values: list[int]) -> None:
    path.write_text("".join(f"{value}\n" for value in values), encoding="ascii")


def checkpoint_stderr(spec: CORPUS.CaseSpec) -> bytes:
    records = b"".join(
        (
            f"[debug] Found exact stackmap record for func_{index}, "
            f"wasm_op={index}, native_return_pc_offset=0x{index + 1:x}\n"
        ).encode("ascii")
        for index in range(spec.frames)
    )
    return (
        b"[info] Checkpoint started\n"
        + records
        + b"[info] Compressing memory\n"
        + b"[info] Compression ratio: 0.25\n"
        + b"[info] Compression time: 1 ms\n"
        + b"[info] Snapshot has been saved to checkpoint.pb\n"
        + b"[info] Checkpoint time has been saved to chkpt-time.txt\n"
    )


def restore_stderr(spec: CORPUS.CaseSpec) -> bytes:
    pages = 2 if spec.profile == "data-segment" else 1
    return (
        f"[info] Decompressing memory: {pages} pages ({pages * 65536} bytes)\n"
        "[info] Checkpoint has been loaded\n"
        f"[info] - call stack: {spec.frames} frames\n"
        f"[info] - value stack: {spec.typed_stack_values} values\n"
        "[info] Restore time has been saved to restore-time.txt\n"
    ).encode("ascii")


def process_observation(case: Path, spec: CORPUS.CaseSpec, role: str) -> bytes:
    stdout = (case / f"{role}.stdout").read_bytes()
    stderr = (case / f"{role}.stderr").read_bytes()
    checkpoint = None
    if role != "control":
        checkpoint = CORPUS.bytes_identity((case / "checkpoint.pb").read_bytes())
    value = {
        "schema": CORPUS.PROCESS_OBSERVATION_SCHEMA,
        "case_id": spec.case_id,
        "role": role,
        "exit_status": 0,
        "stdout": CORPUS.bytes_identity(stdout),
        "stderr": CORPUS.bytes_identity(stderr),
        "checkpoint": checkpoint,
    }
    return CORPUS.canonical_bytes(value) + b"\n"


def build_receipt_payload() -> dict[str, object]:
    source_lock = json.loads(CORPUS.DEFAULT_SOURCE_LOCK.read_text(encoding="utf-8"))
    patch_paths = [item["path"] for item in source_lock["patches"]]
    patch_set = hashlib.sha256(
        "".join(item["sha256"] for item in source_lock["patches"]).encode("ascii")
    ).hexdigest()
    return {
        "schema": "visa-wanco-carrier-build-receipt-v5",
        "revision": source_lock["upstream"]["revision"],
        "patch_set_sha256": patch_set,
        "patches": patch_paths,
        "image_tag": IMAGE_TAG,
        "image_id": IMAGE_ID,
        "platform": source_lock["build"]["platform"],
        "llvm_sys_170_prefix": "/usr/lib/llvm-17",
        "llvm_config_version": "17.0.6",
        "rustc_version": "rustc 1.97.1 (fixture)",
        "cargo_version": "cargo 1.97.1 (fixture)",
        "clang_version": "Debian clang version 17.0.6",
        "hyperfine_version": "hyperfine 1.20.0",
        "wanco_binary_sha256": "1a" * 32,
        "runtime_staticlib_sha256": "2b" * 32,
        "checkpoint_memory_encoding": "lz4-block-exact-length",
        "stackmap_binding": "exact-active-callsite-id",
        "stackmap_layout": "typed-locals-and-value-stack-v2",
        "indirect_call_operands_retained": True,
        "active_data_segments_preserved_on_restore": True,
        "per_frame_callee_saved_registers": True,
        "post_import_checkpoint_points": True,
        "guest_tail_calls_disabled": True,
        "benchmark_subtree_in_build_context": False,
    }


def causal_events(spec: CORPUS.CaseSpec, checkpoint: bytes, container_id: str) -> bytes:
    nonce = CORPUS.expected_post_import_nonce(IMAGE_ID, spec)
    lines = []
    for sequence, event in enumerate(CORPUS.POST_IMPORT_CAUSAL_ORDER, start=1):
        lines.append(
            CORPUS.canonical_bytes(
                {
                    "sequence": sequence,
                    "event": event,
                    "case_id": spec.case_id,
                    "image_id": IMAGE_ID,
                    "nonce": nonce,
                    "container_id": container_id,
                    "checkpoint_sha256": (
                        hashlib.sha256(checkpoint).hexdigest()
                        if sequence == len(CORPUS.POST_IMPORT_CAUSAL_ORDER)
                        else None
                    ),
                }
            )
        )
    return b"\n".join(lines) + b"\n"


def materialize_source(root: Path) -> Path:
    build_receipt = root / "wanco-build.json"
    build_receipt.write_text(
        json.dumps(build_receipt_payload(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    for index, spec in enumerate(CORPUS.CASE_SPECS, start=1):
        case = root / "results" / spec.case_id
        case.mkdir(parents=True)
        control, prefix, suffix = case_streams(spec)
        write_values(case / "control.stdout", control)
        write_values(case / "checkpoint.stdout", prefix)
        write_values(case / "restore.stdout", suffix)
        (case / "control.stderr").write_bytes(b"")
        (case / "checkpoint.stderr").write_bytes(checkpoint_stderr(spec))
        (case / "restore.stderr").write_bytes(restore_stderr(spec))
        checkpoint = checkpoint_payload(spec)
        (case / "checkpoint.pb").write_bytes(checkpoint)
        for role in ("control", "checkpoint", "restore"):
            (case / f"{role}.process.json").write_bytes(
                process_observation(case, spec, role)
            )
        if spec.profile == CORPUS.POST_IMPORT_PROFILE:
            nonce = CORPUS.expected_post_import_nonce(IMAGE_ID, spec)
            container_id = f"{index + 100:064x}"
            (case / "import-entered.txt").write_text(
                f"entered {nonce}\n", encoding="ascii"
            )
            (case / "signal-dispatched.txt").write_text(
                f"signal-dispatched {nonce}\n", encoding="ascii"
            )
            (case / "import-release-observed.txt").write_text(
                f"release-observed {nonce}\n", encoding="ascii"
            )
            (case / "container.id").write_text(f"{container_id}\n", encoding="ascii")
            (case / "signal.stdout").write_text(f"{container_id}\n", encoding="ascii")
            (case / "causal-events.jsonl").write_bytes(
                causal_events(spec, checkpoint, container_id)
            )
    return build_receipt


def build_fixture(root: Path) -> tuple[Path, dict[str, object], dict[str, object]]:
    source = root / "source"
    source.mkdir()
    build_receipt = materialize_source(source)
    artifact = root / "artifact"
    receipt, qualification = CORPUS.build_bundle(
        source_root=source,
        artifact_root=artifact,
        image_tag=IMAGE_TAG,
        image_id=IMAGE_ID,
        wanco_source_lock=CORPUS.DEFAULT_SOURCE_LOCK,
        wanco_build_receipt=build_receipt,
    )
    return artifact / "receipt.json", receipt, qualification


def rewrite_receipt(path: Path, receipt: dict[str, object]) -> None:
    path.write_bytes(CORPUS.canonical_bytes(receipt) + b"\n")


def reference_for(receipt: dict[str, object], case_index: int, role: str) -> dict[str, object]:
    artifacts = receipt["cases"][case_index]["artifacts"]
    if role in CORPUS.CASE_FILE_NAMES or role in CORPUS.PROCESS_FILE_NAMES:
        return artifacts[role]
    return artifacts["post_import_witness"][role]


def reseal(
    receipt_path: Path,
    receipt: dict[str, object],
    case_index: int,
    role: str,
    payload: bytes,
) -> None:
    reference = reference_for(receipt, case_index, role)
    retained = receipt_path.parent.joinpath(*reference["path"].split("/"))
    retained.write_bytes(payload)
    reference.update(CORPUS.bytes_identity(payload))
    rewrite_receipt(receipt_path, receipt)


def reseal_top(
    receipt_path: Path, receipt: dict[str, object], role: str, payload: bytes
) -> None:
    reference = receipt[role]
    retained = receipt_path.parent.joinpath(*reference["path"].split("/"))
    retained.write_bytes(payload)
    reference.update(CORPUS.bytes_identity(payload))
    rewrite_receipt(receipt_path, receipt)


def refresh_process(
    receipt_path: Path, receipt: dict[str, object], case_index: int, role: str
) -> None:
    case_entry = receipt["cases"][case_index]
    spec = CORPUS.CASE_SPECS[case_index]
    artifacts = case_entry["artifacts"]
    case_dir = receipt_path.parent / "raw" / spec.case_id
    payload = process_observation(case_dir, spec, role)
    process_key = f"{role}_process"
    reference = artifacts[process_key]
    retained = receipt_path.parent.joinpath(*reference["path"].split("/"))
    retained.write_bytes(payload)
    reference.update(CORPUS.bytes_identity(payload))
    rewrite_receipt(receipt_path, receipt)


class TypedCorpusTests(unittest.TestCase):
    def test_checkpoint_is_bound_to_matching_aot_stackmaps(self) -> None:
        spec = CORPUS.CASE_SPECS[0]
        application = aot_elf_payload(spec)
        checkpoint = checkpoint_payload(spec)
        compatibility = CORPUS.derive_checkpoint_application_compatibility(
            application,
            checkpoint,
            "production-shaped fixture",
        )
        self.assertEqual(compatibility["frame_count"], spec.frames)
        self.assertEqual(
            compatibility["local_value_count"],
            len(spec.required_local_types),
        )
        self.assertEqual(
            compatibility["stack_value_count"],
            len(spec.expected_stack_types),
        )
        self.assertEqual(
            compatibility["application"],
            CORPUS.bytes_identity(application),
        )
        self.assertEqual(
            compatibility["checkpoint"],
            CORPUS.bytes_identity(checkpoint),
        )

    def test_valid_but_unrelated_checkpoint_is_rejected_by_aot_binding(self) -> None:
        application = aot_elf_payload(CORPUS.CASE_SPECS[0])
        unrelated_checkpoint = checkpoint_payload(CORPUS.CASE_SPECS[3])
        CORPUS.derive_checkpoint_envelope(
            unrelated_checkpoint,
            "valid unrelated checkpoint",
        )
        with self.assertRaisesRegex(
            CORPUS.CorpusFailure,
            "typed state differs|no matching application patchpoint",
        ):
            CORPUS.derive_checkpoint_application_compatibility(
                application,
                unrelated_checkpoint,
                "valid unrelated pair",
            )

    def test_proto3_omitted_zero_frame_scalars_are_accepted(self) -> None:
        spec = CORPUS.CASE_SPECS[0]
        envelope = CORPUS.derive_checkpoint_envelope(
            checkpoint_payload_with_omitted_frame_defaults(spec),
            "proto3 default fixture",
        )
        self.assertEqual(envelope["frame_count"], spec.frames)
        self.assertEqual(envelope["stack_types"], list(spec.expected_stack_types))

    def test_bundle_rederives_locked_twelve_case_corpus(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wanco-typed-v5-") as raw:
            receipt_path, receipt, qualification = build_fixture(Path(raw))
            loaded, rederived = CORPUS.load_and_validate(receipt_path)
            self.assertEqual((loaded, rederived), (receipt, qualification))
            self.assertEqual(len(receipt["cases"]), 12)
            self.assertEqual(len(list(CORPUS.iter_references(receipt))), 140)
            self.assertEqual(
                qualification["wanco_source_lock"],
                CORPUS.bytes_identity(CORPUS.DEFAULT_SOURCE_LOCK.read_bytes()),
            )
            for spec, case in zip(
                CORPUS.CASE_SPECS, qualification["cases"], strict=True
            ):
                self.assertEqual(case["control_values"], list(spec.expected_control))
                self.assertEqual(
                    case["checkpoint_envelope"]["stack_types"],
                    list(spec.expected_stack_types),
                )
                self.assertEqual(
                    case["process_exit_statuses"],
                    {"control": 0, "checkpoint": 0, "restore": 0},
                )

    def test_summary_only_and_noncanonical_receipts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wanco-typed-summary-") as raw:
            receipt_path, receipt, _ = build_fixture(Path(raw))
            changed = copy.deepcopy(receipt)
            changed["schema"] = "visa-wanco-typed-checkpoint-corpus-v4"
            rewrite_receipt(receipt_path, changed)
            with self.assertRaises(CORPUS.CorpusFailure):
                CORPUS.load_and_validate(receipt_path)
            receipt_path.write_bytes(
                json.dumps(receipt, indent=2, sort_keys=True).encode("utf-8") + b"\n"
            )
            with self.assertRaisesRegex(CORPUS.CorpusFailure, "not canonical JSON"):
                CORPUS.load_and_validate(receipt_path)

    def test_semantic_and_process_mutations_are_rejected(self) -> None:
        scenarios = (
            "coordinated-output-reseal",
            "fake-checkpoint",
            "corrupt-lz4",
            "truncated-lz4",
            "short-lz4-output",
            "terminal-lz4-match",
            "late-lz4-match",
            "extra-diagnostic",
            "process-exit",
            "control-stderr",
            "fake-causal-order",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory(
                prefix="wanco-typed-mutation-"
            ) as raw:
                receipt_path, receipt, _ = build_fixture(Path(raw))
                if scenario == "coordinated-output-reseal":
                    reseal(receipt_path, receipt, 0, "control_stdout", b"700\n999\n")
                    refresh_process(receipt_path, receipt, 0, "control")
                elif scenario == "fake-checkpoint":
                    reseal(receipt_path, receipt, 0, "checkpoint", b"forged-checkpoint")
                    refresh_process(receipt_path, receipt, 0, "checkpoint")
                    refresh_process(receipt_path, receipt, 0, "restore")
                elif scenario in {
                    "corrupt-lz4",
                    "truncated-lz4",
                    "short-lz4-output",
                    "terminal-lz4-match",
                    "late-lz4-match",
                }:
                    spec = CORPUS.CASE_SPECS[0]
                    if scenario == "corrupt-lz4":
                        compressed = b"\x00\x00\x00"
                    elif scenario == "truncated-lz4":
                        compressed = b"\xf0"
                    elif scenario == "short-lz4-output":
                        compressed = lz4_literal_block(b"\0" * (65536 - 1))
                    elif scenario == "terminal-lz4-match":
                        compressed = lz4_terminal_match_block(65536)
                    else:
                        compressed = lz4_late_match_block(65536)
                    reseal(
                        receipt_path,
                        receipt,
                        0,
                        "checkpoint",
                        checkpoint_payload(spec, compressed_memory=compressed),
                    )
                    refresh_process(receipt_path, receipt, 0, "checkpoint")
                    refresh_process(receipt_path, receipt, 0, "restore")
                elif scenario == "extra-diagnostic":
                    original = (
                        receipt_path.parent / "raw" / "direct-O0" / "checkpoint.stderr"
                    ).read_bytes()
                    reseal(
                        receipt_path,
                        receipt,
                        0,
                        "checkpoint_stderr",
                        original + b"fatal: forged\n",
                    )
                    refresh_process(receipt_path, receipt, 0, "checkpoint")
                elif scenario == "process-exit":
                    reference = reference_for(receipt, 0, "restore_process")
                    path = receipt_path.parent.joinpath(*reference["path"].split("/"))
                    observation = json.loads(path.read_text(encoding="utf-8"))
                    observation["exit_status"] = 9
                    reseal(
                        receipt_path,
                        receipt,
                        0,
                        "restore_process",
                        CORPUS.canonical_bytes(observation) + b"\n",
                    )
                elif scenario == "control-stderr":
                    reseal(receipt_path, receipt, 0, "control_stderr", b"warning\n")
                    refresh_process(receipt_path, receipt, 0, "control")
                else:
                    index = 9
                    reference = reference_for(receipt, index, "causal_events")
                    path = receipt_path.parent.joinpath(*reference["path"].split("/"))
                    lines = path.read_bytes().splitlines()
                    lines[0], lines[1] = lines[1], lines[0]
                    reseal(
                        receipt_path,
                        receipt,
                        index,
                        "causal_events",
                        b"\n".join(lines) + b"\n",
                    )
                with self.assertRaises(CORPUS.CorpusFailure):
                    CORPUS.load_and_validate(receipt_path)

    def test_fake_build_and_coordinated_source_lock_are_rejected(self) -> None:
        for scenario in ("build-revision", "source-lock-and-build"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory(
                prefix="wanco-typed-build-"
            ) as raw:
                receipt_path, receipt, _ = build_fixture(Path(raw))
                build_ref = receipt["wanco_build_receipt"]
                build_path = receipt_path.parent.joinpath(*build_ref["path"].split("/"))
                build = json.loads(build_path.read_text(encoding="utf-8"))
                build["revision"] = "0" * 40
                reseal_top(
                    receipt_path,
                    receipt,
                    "wanco_build_receipt",
                    json.dumps(build, indent=2, sort_keys=True).encode("utf-8") + b"\n",
                )
                if scenario == "source-lock-and-build":
                    lock_ref = receipt["wanco_source_lock"]
                    lock_path = receipt_path.parent.joinpath(*lock_ref["path"].split("/"))
                    lock = json.loads(lock_path.read_text(encoding="utf-8"))
                    lock["upstream"]["revision"] = "0" * 40
                    reseal_top(
                        receipt_path,
                        receipt,
                        "wanco_source_lock",
                        json.dumps(lock, indent=2, sort_keys=True).encode("utf-8")
                        + b"\n",
                    )
                with self.assertRaises(CORPUS.CorpusFailure):
                    CORPUS.load_and_validate(receipt_path)

    def test_path_security_and_relocation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wanco-typed-path-") as raw:
            root = Path(raw)
            receipt_path, receipt, qualification = build_fixture(root)
            changed = copy.deepcopy(receipt)
            changed["cases"][0]["artifacts"]["checkpoint"]["path"] = "../escape"
            rewrite_receipt(receipt_path, changed)
            with self.assertRaises(CORPUS.CorpusFailure):
                CORPUS.load_and_validate(receipt_path)
            rewrite_receipt(receipt_path, receipt)
            destination = root / "relocated"
            copied, copied_qualification = CORPUS.retain_bundle(
                receipt_path, destination
            )
            self.assertEqual((copied, copied_qualification), (receipt, qualification))


if __name__ == "__main__":
    unittest.main()
