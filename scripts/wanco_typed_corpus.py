#!/usr/bin/env python3
"""Build and independently validate retained Wanco typed-restore evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Mapping, Sequence

import receipt_artifacts as ARTIFACTS
import wanco_process_diagnostics as DIAGNOSTICS


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE_LOCK = ROOT / "third_party" / "wanco" / "source-lock.json"

SCHEMA = "visa-wanco-typed-checkpoint-corpus-v5"
QUALIFICATION_SCHEMA = "visa-wanco-typed-checkpoint-qualification-v2"
POST_IMPORT_WITNESS_SCHEMA = "visa-wanco-post-import-signal-witness-v3"
PROCESS_OBSERVATION_SCHEMA = "visa-wanco-typed-process-observation-v1"
CHECKPOINT_ENVELOPE_SCHEMA = "visa-wanco-checkpoint-envelope-v1"
CHECKPOINT_APPLICATION_SCHEMA = (
    "visa-wanco-checkpoint-application-compatibility-v1"
)
POST_IMPORT_PROFILE = "post-import-root"
POST_IMPORT_ENTRY_MARKER = 1003
POST_IMPORT_CHECKPOINT_MARKER = 1005
POST_IMPORT_CAUSAL_ORDER = [
    "host-import-entered",
    "runner-dispatched-sigusr1",
    "host-observed-post-signal-release",
    "post-import-exact-callsite-captured",
]

MAX_RECEIPT_BYTES = 1024 * 1024
MAX_BUILD_RECEIPT_BYTES = 256 * 1024
MAX_SOURCE_LOCK_BYTES = 512 * 1024
MAX_STDOUT_BYTES = 64 * 1024
MAX_STDERR_BYTES = 2 * 1024 * 1024
MAX_WITNESS_BYTES = 512
MAX_CAUSAL_EVENTS_BYTES = 8 * 1024
MAX_PROCESS_OBSERVATION_BYTES = 4 * 1024
MAX_CHECKPOINT_BYTES = 16 * 1024 * 1024
MAX_DECOMPRESSED_MEMORY_BYTES = 64 * 1024 * 1024
MAX_RETAINED_BYTES = 64 * 1024 * 1024
MAX_ELF_SECTIONS = 65535
MAX_STACKMAP_FUNCTIONS = 1_000_000
MAX_STACKMAP_CONSTANTS = 1_000_000
MAX_STACKMAP_RECORDS = 1_000_000
MAX_STACKMAP_LOCATIONS = 65535
MAX_STACKMAP_LIVE_OUTS = 65535

STACKMAP_LAYOUT_V2 = 0x57414E43
LLVM_STACKMAP_CONSTANT = 4
LLVM_STACKMAP_VALUE_LOCATIONS = {1, 2, 3}
STACKMAP_VALUE_TYPE_NAMES = {0: "i32", 1: "i64", 2: "f32", 3: "f64"}

CASE_FILE_NAMES = {
    "control_stdout": "control.stdout",
    "control_stderr": "control.stderr",
    "checkpoint_stdout": "checkpoint.stdout",
    "restore_stdout": "restore.stdout",
    "checkpoint_stderr": "checkpoint.stderr",
    "restore_stderr": "restore.stderr",
    "checkpoint": "checkpoint.pb",
}
PROCESS_FILE_NAMES = {
    "control_process": "control.process.json",
    "checkpoint_process": "checkpoint.process.json",
    "restore_process": "restore.process.json",
}
WITNESS_FILE_NAMES = {
    "import_entered": "import-entered.txt",
    "signal_dispatch": "signal.stdout",
    "release_gate": "signal-dispatched.txt",
    "import_release_observed": "import-release-observed.txt",
    "container_identity": "container.id",
    "causal_events": "causal-events.jsonl",
}

VALUE_TYPE_NAMES = {1: "i32", 2: "i64", 3: "f32", 4: "f64"}


class CorpusFailure(RuntimeError):
    """The retained typed-restore corpus is incomplete or inconsistent."""


@dataclass(frozen=True)
class CaseSpec:
    profile: str
    optimization: int
    marker: int
    frames: int
    typed_stack_values: int
    expected_control: tuple[int, ...]
    expected_stack_types: tuple[str, ...]
    required_local_types: tuple[str, ...]

    @property
    def case_id(self) -> str:
        return f"{self.profile}-O{self.optimization}"


CASE_SPECS = tuple(
    CaseSpec(
        profile,
        optimization,
        marker,
        frames,
        len(stack_types),
        control,
        stack_types,
        local_types,
    )
    for profile, marker, frames, control, stack_types, local_types in (
        (
            "direct",
            703,
            6,
            (*range(700, 720), -1174066176),
            ("f64", "i64", "i32", "f32"),
            ("i32", "i64", "f32", "f64"),
        ),
        (
            "indirect",
            803,
            3,
            (*range(800, 812), 1533704661),
            ("i64", "i32", "i32"),
            ("i32", "i64", "f32", "f64"),
        ),
        (
            "data-segment",
            903,
            4,
            (*range(900, 912), 908334810, 990139514),
            (),
            ("i32", "i64", "f32", "f64"),
        ),
        (
            POST_IMPORT_PROFILE,
            POST_IMPORT_CHECKPOINT_MARKER,
            1,
            (POST_IMPORT_ENTRY_MARKER, POST_IMPORT_CHECKPOINT_MARKER, 1004),
            (),
            (),
        ),
    )
    for optimization in range(3)
)


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def bytes_identity(raw: bytes) -> dict[str, object]:
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


def reference_identity(value: object, label: str = "artifact") -> dict[str, object]:
    reference = ARTIFACTS.validate_reference(value, label)
    return {"sha256": reference["sha256"], "size": reference["size"]}


def expected_post_import_nonce(image_id: str, spec: CaseSpec) -> str:
    raw = f"{image_id}:{spec.profile}:O{spec.optimization}\n".encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _parse_canonical_json(raw: bytes, label: str) -> object:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CorpusFailure(f"{label} is invalid JSON: {error}") from error
    if canonical_bytes(value) + b"\n" != raw:
        raise CorpusFailure(f"{label} is not canonical JSON")
    return value


def _read_varint(raw: bytes, offset: int, label: str) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(raw):
            raise CorpusFailure(f"{label} contains a truncated protobuf varint")
        byte = raw[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
    raise CorpusFailure(f"{label} contains an oversized protobuf varint")


def _protobuf_fields(
    raw: bytes, label: str
) -> list[tuple[int, int, int | bytes]]:
    fields: list[tuple[int, int, int | bytes]] = []
    offset = 0
    while offset < len(raw):
        key, offset = _read_varint(raw, offset, label)
        field = key >> 3
        wire = key & 7
        if field == 0:
            raise CorpusFailure(f"{label} contains protobuf field zero")
        if wire == 0:
            value, offset = _read_varint(raw, offset, label)
        elif wire == 1:
            if offset + 8 > len(raw):
                raise CorpusFailure(f"{label} contains a truncated fixed64 field")
            value = raw[offset : offset + 8]
            offset += 8
        elif wire == 2:
            size, offset = _read_varint(raw, offset, label)
            if size > len(raw) - offset:
                raise CorpusFailure(f"{label} contains a truncated bytes field")
            value = raw[offset : offset + size]
            offset += size
        elif wire == 5:
            if offset + 4 > len(raw):
                raise CorpusFailure(f"{label} contains a truncated fixed32 field")
            value = raw[offset : offset + 4]
            offset += 4
        else:
            raise CorpusFailure(f"{label} contains unsupported protobuf wire type {wire}")
        fields.append((field, wire, value))
    return fields


def _protobuf_value_type(raw: bytes, label: str) -> str:
    fields = _protobuf_fields(raw, label)
    if any(field not in {1, 2, 3, 4, 5} for field, _, _ in fields):
        raise CorpusFailure(f"{label} contains an unknown value field")
    type_fields = [value for field, wire, value in fields if field == 1 and wire == 0]
    if len(type_fields) != 1 or not isinstance(type_fields[0], int):
        raise CorpusFailure(f"{label} does not contain exactly one value type")
    value_type = type_fields[0]
    expected_field = {1: (2, 0), 2: (3, 0), 3: (4, 5), 4: (5, 1)}.get(
        value_type
    )
    if expected_field is None:
        raise CorpusFailure(f"{label} contains an unsupported value type")
    payload_fields = [(field, wire) for field, wire, _ in fields if field != 1]
    if payload_fields != [expected_field]:
        raise CorpusFailure(f"{label} value payload does not match its declared type")
    return VALUE_TYPE_NAMES[value_type]


def _protobuf_int32(value: int, label: str) -> int:
    if value <= 0x7FFFFFFF:
        return value
    if 0xFFFFFFFF80000000 <= value <= 0xFFFFFFFFFFFFFFFF:
        return value - (1 << 64)
    raise CorpusFailure(f"{label} is outside the protobuf int32 range")


def _protobuf_frame(raw: bytes, label: str) -> dict[str, object]:
    fields = _protobuf_fields(raw, label)
    if any(field not in {1, 2, 3, 4} for field, _, _ in fields):
        raise CorpusFailure(f"{label} contains an unknown frame field")
    scalars_by_field: dict[int, list[int]] = {}
    for field, name in ((1, "function"), (2, "program counter")):
        scalars = [value for number, wire, value in fields if number == field and wire == 0]
        wrong_wire = [wire for number, wire, _ in fields if number == field and wire != 0]
        if wrong_wire or len(scalars) > 1 or any(
            not isinstance(value, int) for value in scalars
        ):
            raise CorpusFailure(f"{label} has a malformed {name}")
        scalars_by_field[field] = [
            _protobuf_int32(value, f"{label} {name}")
            for value in scalars
            if isinstance(value, int)
        ]
    locals_raw = [
        value for field, wire, value in fields if field == 3 and wire == 2
    ]
    stack_raw = [
        value for field, wire, value in fields if field == 4 and wire == 2
    ]
    if any(not isinstance(value, bytes) for value in [*locals_raw, *stack_raw]):
        raise CorpusFailure(f"{label} has malformed typed values")
    local_types = [
        _protobuf_value_type(value, f"{label} local[{index}]")
        for index, value in enumerate(locals_raw)
        if isinstance(value, bytes)
    ]
    stack_types = [
        _protobuf_value_type(value, f"{label} stack[{index}]")
        for index, value in enumerate(stack_raw)
        if isinstance(value, bytes)
    ]
    return {
        "function_index": scalars_by_field[1][0] if scalars_by_field[1] else 0,
        "program_counter": scalars_by_field[2][0] if scalars_by_field[2] else 0,
        "local_types": local_types,
        "stack_types": stack_types,
    }


def _checkpoint_frames(raw: bytes, label: str) -> list[dict[str, object]]:
    fields = _protobuf_fields(raw, label)
    if any(field not in {1, 2, 3, 4, 5, 6} for field, _, _ in fields):
        raise CorpusFailure(f"{label} contains an unknown checkpoint field")
    frames_raw = [value for field, wire, value in fields if field == 1 and wire == 2]
    if not frames_raw or any(not isinstance(value, bytes) for value in frames_raw):
        raise CorpusFailure(f"{label} contains no typed frames")
    return [
        _protobuf_frame(frame, f"{label} frame[{index}]")
        for index, frame in enumerate(frames_raw)
        if isinstance(frame, bytes)
    ]


def _unpack_from(
    format_string: str, raw: bytes, offset: int, label: str
) -> tuple[tuple[object, ...], int]:
    size = struct.calcsize(format_string)
    if offset > len(raw) - size:
        raise CorpusFailure(f"{label} is truncated")
    return struct.unpack_from(format_string, raw, offset), offset + size


def _elf_stackmap_section(application: bytes, label: str) -> bytes:
    if len(application) < 64 or application[:4] != b"\x7fELF":
        raise CorpusFailure(f"{label} is not an ELF executable")
    if application[4:7] != b"\x02\x01\x01":
        raise CorpusFailure(f"{label} is not little-endian ELF64")
    header, _ = _unpack_from(
        "<16sHHIQQQIHHHHHH",
        application,
        0,
        f"{label} ELF header",
    )
    (
        _,
        elf_type,
        machine,
        version,
        _,
        _,
        section_offset,
        _,
        elf_header_size,
        _,
        _,
        section_entry_size,
        section_count,
        string_table_index,
    ) = header
    if (
        elf_type != 2
        or machine != 62
        or version != 1
        or elf_header_size != 64
        or section_entry_size != 64
    ):
        raise CorpusFailure(f"{label} has an unsupported ELF64 executable header")
    if (
        not isinstance(section_count, int)
        or section_count <= 0
        or section_count > MAX_ELF_SECTIONS
        or not isinstance(string_table_index, int)
        or string_table_index <= 0
        or string_table_index >= section_count
        or not isinstance(section_offset, int)
        or section_offset > len(application) - section_count * section_entry_size
    ):
        raise CorpusFailure(f"{label} has an invalid ELF section table")

    sections: list[tuple[object, ...]] = []
    for index in range(section_count):
        section, _ = _unpack_from(
            "<IIQQQQIIQQ",
            application,
            section_offset + index * section_entry_size,
            f"{label} ELF section[{index}]",
        )
        sections.append(section)

    string_section = sections[string_table_index]
    string_offset = string_section[4]
    string_size = string_section[5]
    if (
        string_section[1] != 3
        or not isinstance(string_offset, int)
        or not isinstance(string_size, int)
        or string_size <= 0
        or string_offset > len(application) - string_size
    ):
        raise CorpusFailure(f"{label} has an invalid section-name string table")
    names = application[string_offset : string_offset + string_size]

    matches: list[tuple[object, ...]] = []
    for index, section in enumerate(sections):
        name_offset = section[0]
        if not isinstance(name_offset, int) or name_offset >= len(names):
            raise CorpusFailure(f"{label} ELF section[{index}] has an invalid name")
        name_end = names.find(b"\0", name_offset)
        if name_end < 0:
            raise CorpusFailure(f"{label} ELF section[{index}] name is unterminated")
        if names[name_offset:name_end] == b".llvm_stackmaps":
            matches.append(section)
    if len(matches) != 1:
        raise CorpusFailure(
            f"{label} must contain exactly one .llvm_stackmaps section"
        )
    stackmap = matches[0]
    stackmap_offset = stackmap[4]
    stackmap_size = stackmap[5]
    if (
        stackmap[1] != 1
        or not isinstance(stackmap_offset, int)
        or not isinstance(stackmap_size, int)
        or stackmap_size <= 0
        or stackmap_size > MAX_RETAINED_BYTES
        or stackmap_offset > len(application) - stackmap_size
    ):
        raise CorpusFailure(f"{label} has an invalid .llvm_stackmaps section")
    return application[stackmap_offset : stackmap_offset + stackmap_size]


def _stackmap_records(
    raw: bytes, label: str
) -> dict[int, tuple[tuple[int, int, int, int], ...]]:
    header, offset = _unpack_from("<BBHIII", raw, 0, f"{label} header")
    version, reserved0, reserved1, function_count, constant_count, record_count = (
        header
    )
    if version != 3 or reserved0 != 0 or reserved1 != 0:
        raise CorpusFailure(f"{label} has an unsupported LLVM stackmap header")
    if (
        not isinstance(function_count, int)
        or function_count > MAX_STACKMAP_FUNCTIONS
        or not isinstance(constant_count, int)
        or constant_count > MAX_STACKMAP_CONSTANTS
        or not isinstance(record_count, int)
        or record_count > MAX_STACKMAP_RECORDS
    ):
        raise CorpusFailure(f"{label} exceeds the stackmap validation bounds")

    declared_records = 0
    for index in range(function_count):
        function, offset = _unpack_from(
            "<QQQ", raw, offset, f"{label} function[{index}]"
        )
        declared_records += function[2]
        if declared_records > MAX_STACKMAP_RECORDS:
            raise CorpusFailure(f"{label} function records exceed the validation bound")
    if declared_records != record_count:
        raise CorpusFailure(f"{label} function and header record counts differ")

    constant_bytes = constant_count * 8
    if offset > len(raw) - constant_bytes:
        raise CorpusFailure(f"{label} constants are truncated")
    offset += constant_bytes

    records: dict[int, tuple[tuple[int, int, int, int], ...]] = {}
    for record_index in range(record_count):
        record_header, offset = _unpack_from(
            "<QIHH", raw, offset, f"{label} record[{record_index}] header"
        )
        patchpoint_id, _, record_reserved, location_count = record_header
        if record_reserved != 0 or location_count > MAX_STACKMAP_LOCATIONS:
            raise CorpusFailure(f"{label} record[{record_index}] is malformed")
        locations: list[tuple[int, int, int, int]] = []
        for location_index in range(location_count):
            location, offset = _unpack_from(
                "<BBHHHi",
                raw,
                offset,
                f"{label} record[{record_index}] location[{location_index}]",
            )
            kind, location_reserved, size, register, reserved, value = location
            if location_reserved != 0 or reserved != 0 or kind not in {1, 2, 3, 4, 5}:
                raise CorpusFailure(
                    f"{label} record[{record_index}] has an invalid location"
                )
            locations.append((kind, size, register, value))
        if offset % 8:
            padding = 8 - offset % 8
            if padding != 4 or raw[offset : offset + padding] != b"\0" * padding:
                raise CorpusFailure(f"{label} record[{record_index}] has invalid padding")
            offset += padding
        live_header, offset = _unpack_from(
            "<HH", raw, offset, f"{label} record[{record_index}] live-out header"
        )
        live_padding, live_count = live_header
        if live_padding != 0 or live_count > MAX_STACKMAP_LIVE_OUTS:
            raise CorpusFailure(f"{label} record[{record_index}] live-outs are malformed")
        live_bytes = live_count * 4
        if offset > len(raw) - live_bytes:
            raise CorpusFailure(f"{label} record[{record_index}] live-outs are truncated")
        for live_offset in range(offset, offset + live_bytes, 4):
            _, live_reserved, _ = struct.unpack_from("<HBB", raw, live_offset)
            if live_reserved != 0:
                raise CorpusFailure(
                    f"{label} record[{record_index}] has an invalid live-out"
                )
        offset += live_bytes
        if offset % 8:
            padding = 8 - offset % 8
            if padding != 4 or raw[offset : offset + padding] != b"\0" * padding:
                raise CorpusFailure(f"{label} record[{record_index}] has invalid padding")
            offset += padding
        if patchpoint_id in records:
            raise CorpusFailure(f"{label} contains a duplicate patchpoint ID")
        records[patchpoint_id] = tuple(locations)

    trailing = raw[offset:]
    if len(trailing) >= 8 or any(trailing):
        raise CorpusFailure(f"{label} contains trailing non-record bytes")
    return records


def _constant_location(
    location: tuple[int, int, int, int], label: str
) -> int:
    kind, _, _, value = location
    if kind != LLVM_STACKMAP_CONSTANT or value < 0:
        raise CorpusFailure(f"{label} is not a non-negative constant location")
    return value


def _typed_stackmap(
    locations: tuple[tuple[int, int, int, int], ...], label: str
) -> tuple[list[str], list[str]]:
    if len(locations) < 3:
        raise CorpusFailure(f"{label} lacks the typed stackmap header")
    layout = _constant_location(locations[0], f"{label} layout")
    local_count = _constant_location(locations[1], f"{label} local count")
    stack_count = _constant_location(locations[2], f"{label} stack count")
    if layout != STACKMAP_LAYOUT_V2:
        raise CorpusFailure(f"{label} has an unsupported typed stackmap layout")
    if len(locations) != 3 + 2 * (local_count + stack_count):
        raise CorpusFailure(f"{label} typed location count differs")

    types: list[str] = []
    offset = 3
    for value_index in range(local_count + stack_count):
        type_code = _constant_location(
            locations[offset], f"{label} value[{value_index}] type"
        )
        value_kind = locations[offset + 1][0]
        if type_code not in STACKMAP_VALUE_TYPE_NAMES:
            raise CorpusFailure(f"{label} contains an unsupported Wasm value type")
        if value_kind not in LLVM_STACKMAP_VALUE_LOCATIONS:
            raise CorpusFailure(f"{label} value[{value_index}] is not restorable")
        types.append(STACKMAP_VALUE_TYPE_NAMES[type_code])
        offset += 2
    return types[:local_count], types[local_count:]


def _lz4_length(
    raw: bytes, offset: int, base: int, label: str
) -> tuple[int, int]:
    length = base
    if base != 15:
        return length, offset
    while True:
        if offset >= len(raw):
            raise CorpusFailure(f"{label} contains a truncated LZ4 length")
        extension = raw[offset]
        offset += 1
        length += extension
        if extension != 255:
            return length, offset


def _validate_lz4_block(raw: bytes, expected_size: int, label: str) -> None:
    if not raw:
        raise CorpusFailure(f"{label} contains an empty LZ4 block")
    if expected_size <= 0 or expected_size > MAX_DECOMPRESSED_MEMORY_BYTES:
        raise CorpusFailure(f"{label} LZ4 output exceeds the validation bound")
    output = bytearray()
    offset = 0
    saw_final_literals = False
    last_match_start: int | None = None
    while offset < len(raw):
        token = raw[offset]
        offset += 1
        literal_length, offset = _lz4_length(
            raw, offset, token >> 4, label
        )
        if literal_length > len(raw) - offset:
            raise CorpusFailure(f"{label} contains truncated LZ4 literals")
        if literal_length > expected_size - len(output):
            raise CorpusFailure(f"{label} LZ4 literals exceed the declared memory")
        output.extend(raw[offset : offset + literal_length])
        offset += literal_length
        if offset == len(raw):
            if literal_length < 5:
                raise CorpusFailure(
                    f"{label} LZ4 final sequence has fewer than five literals"
                )
            saw_final_literals = True
            break
        if len(raw) - offset < 2:
            raise CorpusFailure(f"{label} contains a truncated LZ4 match offset")
        match_offset = raw[offset] | (raw[offset + 1] << 8)
        offset += 2
        if match_offset == 0 or match_offset > len(output):
            raise CorpusFailure(f"{label} contains an invalid LZ4 match offset")
        match_length, offset = _lz4_length(
            raw, offset, token & 0x0F, label
        )
        match_length += 4
        if match_length > expected_size - len(output):
            raise CorpusFailure(f"{label} LZ4 match exceeds the declared memory")
        last_match_start = len(output)
        pattern = bytes(output[-match_offset:])
        repetitions = (match_length + len(pattern) - 1) // len(pattern)
        output.extend((pattern * repetitions)[:match_length])
    if not saw_final_literals:
        raise CorpusFailure(f"{label} LZ4 block does not end in a literal sequence")
    if len(output) != expected_size:
        raise CorpusFailure(
            f"{label} LZ4 output length differs from the declared memory"
        )
    if last_match_start is not None and last_match_start > expected_size - 12:
        raise CorpusFailure(
            f"{label} LZ4 final match begins fewer than twelve output bytes from the end"
        )


def derive_checkpoint_envelope(raw: bytes, label: str) -> dict[str, object]:
    fields = _protobuf_fields(raw, label)
    if any(field not in {1, 2, 3, 4, 5, 6} for field, _, _ in fields):
        raise CorpusFailure(f"{label} contains an unknown checkpoint field")
    frames_raw = [value for field, wire, value in fields if field == 1 and wire == 2]
    if not frames_raw or any(not isinstance(value, bytes) for value in frames_raw):
        raise CorpusFailure(f"{label} contains no typed frames")
    memory_sizes = [
        value for field, wire, value in fields if field == 4 and wire == 0
    ]
    compressed = [value for field, wire, value in fields if field == 5 and wire == 2]
    plain = [value for field, _, value in fields if field == 6]
    if (
        len(memory_sizes) != 1
        or not isinstance(memory_sizes[0], int)
        or memory_sizes[0] <= 0
        or len(compressed) != 1
        or not isinstance(compressed[0], bytes)
        or not compressed[0]
        or plain
    ):
        raise CorpusFailure(f"{label} lacks one valid LZ4 memory envelope")
    memory_pages = memory_sizes[0]
    memory_bytes = memory_pages * 65536
    compressed_bytes = len(compressed[0])
    if compressed_bytes > memory_bytes + memory_bytes // 255 + 16:
        raise CorpusFailure(f"{label} compressed memory exceeds the LZ4 bound")
    _validate_lz4_block(compressed[0], memory_bytes, label)
    local_types: list[str] = []
    stack_types: list[str] = []
    for index, frame in enumerate(frames_raw):
        assert isinstance(frame, bytes)
        decoded = _protobuf_frame(frame, f"{label} frame[{index}]")
        local_types.extend(decoded["local_types"])
        stack_types.extend(decoded["stack_types"])
    globals_raw = [value for field, wire, value in fields if field == 2 and wire == 2]
    for index, value in enumerate(globals_raw):
        if not isinstance(value, bytes):
            raise CorpusFailure(f"{label} has a malformed global")
        _protobuf_value_type(value, f"{label} global[{index}]")
    for field, wire, value in fields:
        if field != 3:
            continue
        if wire == 0 and isinstance(value, int):
            continue
        if wire == 2 and isinstance(value, bytes):
            offset = 0
            while offset < len(value):
                _, offset = _read_varint(value, offset, f"{label} table")
            continue
        raise CorpusFailure(f"{label} has a malformed table")
    return {
        "schema": CHECKPOINT_ENVELOPE_SCHEMA,
        **bytes_identity(raw),
        "frame_count": len(frames_raw),
        "local_value_count": len(local_types),
        "local_types_present": [
            name for name in VALUE_TYPE_NAMES.values() if name in set(local_types)
        ],
        "stack_value_count": len(stack_types),
        "stack_types": stack_types,
        "memory_pages": memory_pages,
        "memory_encoding": "lz4-block-exact-length",
        "compressed_memory_bytes": compressed_bytes,
    }


def derive_checkpoint_application_compatibility(
    application: bytes, checkpoint: bytes, label: str
) -> dict[str, object]:
    """Independently bind every checkpoint frame to its executable stackmap."""

    derive_checkpoint_envelope(checkpoint, f"{label} checkpoint")
    frames = _checkpoint_frames(checkpoint, f"{label} checkpoint")
    stackmap_bytes = _elf_stackmap_section(application, f"{label} application")
    records = _stackmap_records(
        stackmap_bytes, f"{label} application .llvm_stackmaps"
    )

    matched_ids: list[str] = []
    local_count = 0
    stack_count = 0
    for index, frame in enumerate(frames):
        function_index = frame["function_index"]
        program_counter = frame["program_counter"]
        assert isinstance(function_index, int)
        assert isinstance(program_counter, int)
        if function_index < 0:
            raise CorpusFailure(
                f"{label} checkpoint frame[{index}] has a negative function index"
            )
        patchpoint_id = (
            ((function_index & 0xFFFFFFFF) << 32)
            | (program_counter & 0xFFFFFFFF)
        )
        locations = records.get(patchpoint_id)
        if locations is None:
            raise CorpusFailure(
                f"{label} checkpoint frame[{index}] has no matching application "
                f"patchpoint 0x{patchpoint_id:016x}"
            )
        stackmap_locals, stackmap_stack = _typed_stackmap(
            locations,
            f"{label} application patchpoint 0x{patchpoint_id:016x}",
        )
        checkpoint_locals = frame["local_types"]
        checkpoint_stack = frame["stack_types"]
        if (
            stackmap_locals != checkpoint_locals
            or stackmap_stack != checkpoint_stack
        ):
            raise CorpusFailure(
                f"{label} checkpoint frame[{index}] typed state differs from "
                f"application patchpoint 0x{patchpoint_id:016x}"
            )
        matched_ids.append(f"{patchpoint_id:016x}")
        local_count += len(stackmap_locals)
        stack_count += len(stackmap_stack)

    return {
        "schema": CHECKPOINT_APPLICATION_SCHEMA,
        "application": bytes_identity(application),
        "checkpoint": bytes_identity(checkpoint),
        "stackmap": bytes_identity(stackmap_bytes),
        "frame_count": len(frames),
        "matched_patchpoint_ids": matched_ids,
        "local_value_count": local_count,
        "stack_value_count": stack_count,
    }


def _load_source_lock(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CorpusFailure(f"{label} is invalid JSON: {error}") from error
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "upstream",
        "patches",
        "qualification",
        "build",
    }:
        raise CorpusFailure(f"{label} has the wrong fields")
    if value["schema"] != "visa-wanco-carrier-source-lock-v3":
        raise CorpusFailure(f"{label} has an unsupported schema")
    return value


def _validate_build_receipt(
    raw: bytes,
    *,
    source_lock_raw: bytes,
    receipt: Mapping[str, object],
) -> dict[str, object]:
    try:
        build = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CorpusFailure(f"Wanco build receipt is invalid JSON: {error}") from error
    required = {
        "schema",
        "revision",
        "patch_set_sha256",
        "patches",
        "image_tag",
        "image_id",
        "platform",
        "llvm_sys_170_prefix",
        "llvm_config_version",
        "rustc_version",
        "cargo_version",
        "clang_version",
        "hyperfine_version",
        "wanco_binary_sha256",
        "runtime_staticlib_sha256",
        "checkpoint_memory_encoding",
        "stackmap_binding",
        "stackmap_layout",
        "indirect_call_operands_retained",
        "active_data_segments_preserved_on_restore",
        "per_frame_callee_saved_registers",
        "post_import_checkpoint_points",
        "guest_tail_calls_disabled",
        "benchmark_subtree_in_build_context",
    }
    if not isinstance(build, dict) or set(build) != required:
        raise CorpusFailure("Wanco build receipt does not contain the exact v5 fields")
    lock = _load_source_lock(source_lock_raw, "retained Wanco source lock")
    upstream = lock["upstream"]
    patches = lock["patches"]
    qualification = lock["qualification"]
    locked_build = lock["build"]
    if (
        not isinstance(upstream, dict)
        or not isinstance(patches, list)
        or not isinstance(qualification, dict)
        or not isinstance(locked_build, dict)
    ):
        raise CorpusFailure("retained Wanco source lock is malformed")
    patch_paths: list[str] = []
    patch_digests: list[str] = []
    for patch in patches:
        if not isinstance(patch, dict):
            raise CorpusFailure("retained Wanco patch entry is malformed")
        path = patch.get("path")
        digest = patch.get("sha256")
        if (
            not isinstance(path, str)
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise CorpusFailure("retained Wanco patch identity is malformed")
        patch_paths.append(path)
        patch_digests.append(digest)
    patch_set = hashlib.sha256("".join(patch_digests).encode("ascii")).hexdigest()
    for digest_field in ("wanco_binary_sha256", "runtime_staticlib_sha256"):
        if re.fullmatch(r"[0-9a-f]{64}", str(build[digest_field])) is None:
            raise CorpusFailure(f"Wanco build receipt has an invalid {digest_field}")
    if (
        build["schema"] != "visa-wanco-carrier-build-receipt-v5"
        or build["revision"] != upstream.get("revision")
        or build["patch_set_sha256"] != patch_set
        or build["patches"] != patch_paths
        or build["image_tag"] != receipt["image_tag"]
        or build["image_id"] != receipt["image_id"]
        or build["platform"] != locked_build.get("platform")
        or build["llvm_sys_170_prefix"] != "/usr/lib/llvm-17"
        or not isinstance(build["llvm_config_version"], str)
        or not build["llvm_config_version"].startswith("17.")
        or not isinstance(build["rustc_version"], str)
        or "1.97.1" not in build["rustc_version"]
        or not isinstance(build["cargo_version"], str)
        or "1.97.1" not in build["cargo_version"]
        or not isinstance(build["clang_version"], str)
        or not build["clang_version"]
        or build["hyperfine_version"] != "hyperfine 1.20.0"
        or build["checkpoint_memory_encoding"] != "lz4-block-exact-length"
        or build["stackmap_binding"] != "exact-active-callsite-id"
        or build["stackmap_layout"] != "typed-locals-and-value-stack-v2"
        or build["indirect_call_operands_retained"] is not True
        or build["active_data_segments_preserved_on_restore"] is not True
        or build["per_frame_callee_saved_registers"] is not True
        or build["post_import_checkpoint_points"] is not True
        or build["guest_tail_calls_disabled"] is not True
        or build["benchmark_subtree_in_build_context"] is not False
        or qualification.get("schema") != SCHEMA
        or qualification.get("case_count") != len(CASE_SPECS)
    ):
        raise CorpusFailure("Wanco build receipt differs from the retained source lock")
    return build


def _case_relative(spec: CaseSpec, name: str) -> str:
    return f"raw/{spec.case_id}/{name}"


def _require_reference_path(value: object, expected: str, label: str) -> None:
    try:
        reference = ARTIFACTS.validate_reference(value, label)
    except ARTIFACTS.ArtifactError as error:
        raise CorpusFailure(str(error)) from error
    if reference["path"] != expected:
        raise CorpusFailure(f"{label} must use the canonical path {expected}")


def _validate_case_structure(case: object, spec: CaseSpec) -> None:
    if not isinstance(case, dict) or set(case) != {
        "case_id",
        "profile",
        "optimization",
        "artifacts",
    }:
        raise CorpusFailure(f"typed corpus case {spec.case_id} has the wrong fields")
    if (
        case["case_id"] != spec.case_id
        or case["profile"] != spec.profile
        or case["optimization"] != spec.optimization
    ):
        raise CorpusFailure(f"typed corpus case {spec.case_id} changed its contract")
    artifacts = case["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != {
        *CASE_FILE_NAMES,
        *PROCESS_FILE_NAMES,
        "post_import_witness",
    }:
        raise CorpusFailure(f"{spec.case_id} artifact manifest has the wrong fields")
    for role, name in CASE_FILE_NAMES.items():
        _require_reference_path(
            artifacts[role], _case_relative(spec, name), f"{spec.case_id} {role}"
        )
    for role, name in PROCESS_FILE_NAMES.items():
        _require_reference_path(
            artifacts[role], _case_relative(spec, name), f"{spec.case_id} {role}"
        )
    witness = artifacts["post_import_witness"]
    if spec.profile != POST_IMPORT_PROFILE:
        if witness is not None:
            raise CorpusFailure(f"{spec.case_id} unexpectedly contains witness artifacts")
        return
    if not isinstance(witness, dict) or set(witness) != set(WITNESS_FILE_NAMES):
        raise CorpusFailure(f"{spec.case_id} witness manifest has the wrong fields")
    for role, name in WITNESS_FILE_NAMES.items():
        _require_reference_path(
            witness[role], _case_relative(spec, name), f"{spec.case_id} {role}"
        )


def iter_references(receipt: Mapping[str, object]) -> Iterator[dict[str, object]]:
    source_lock = receipt["wanco_source_lock"]
    build = receipt["wanco_build_receipt"]
    assert isinstance(source_lock, dict)
    assert isinstance(build, dict)
    yield source_lock
    yield build
    cases = receipt["cases"]
    assert isinstance(cases, list)
    for case in cases:
        assert isinstance(case, dict)
        artifacts = case["artifacts"]
        assert isinstance(artifacts, dict)
        for role in CASE_FILE_NAMES:
            reference = artifacts[role]
            assert isinstance(reference, dict)
            yield reference
        for role in PROCESS_FILE_NAMES:
            reference = artifacts[role]
            assert isinstance(reference, dict)
            yield reference
        witness = artifacts["post_import_witness"]
        if witness is not None:
            assert isinstance(witness, dict)
            for role in WITNESS_FILE_NAMES:
                reference = witness[role]
                assert isinstance(reference, dict)
                yield reference


def validate_receipt_structure(receipt: object) -> None:
    if not isinstance(receipt, dict) or set(receipt) != {
        "schema",
        "image_tag",
        "image_id",
        "wanco_source_lock",
        "wanco_build_receipt",
        "cases",
    }:
        raise CorpusFailure("typed corpus receipt has the wrong fields")
    if receipt["schema"] != SCHEMA:
        raise CorpusFailure("unsupported typed corpus receipt schema")
    if not isinstance(receipt["image_tag"], str) or not receipt["image_tag"]:
        raise CorpusFailure("typed corpus image tag is empty")
    if (
        not isinstance(receipt["image_id"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", receipt["image_id"]) is None
    ):
        raise CorpusFailure("typed corpus image identity is invalid")
    _require_reference_path(
        receipt["wanco_source_lock"],
        "inputs/wanco-source-lock.json",
        "Wanco source lock",
    )
    _require_reference_path(
        receipt["wanco_build_receipt"],
        "inputs/wanco-build-receipt.json",
        "Wanco build receipt",
    )
    cases = receipt["cases"]
    if not isinstance(cases, list) or len(cases) != len(CASE_SPECS):
        raise CorpusFailure("typed corpus must contain exactly twelve cases")
    for case, spec in zip(cases, CASE_SPECS, strict=True):
        _validate_case_structure(case, spec)
    paths: list[str] = []
    for reference in iter_references(receipt):
        path = reference["path"]
        assert isinstance(path, str)
        paths.append(path)
    if len(paths) != len(set(paths)):
        raise CorpusFailure("typed corpus contains aliased artifact paths")


def _read_reference(
    artifact_root: Path,
    value: object,
    label: str,
    *,
    budget: ARTIFACTS.ReadBudget,
    max_bytes: int,
) -> bytes:
    try:
        return ARTIFACTS.read_reference(
            artifact_root,
            value,
            label,
            budget=budget,
            max_bytes=max_bytes,
        )
    except ARTIFACTS.ArtifactError as error:
        raise CorpusFailure(str(error)) from error


def _parse_values(raw: bytes, label: str) -> list[int]:
    if not raw or not raw.endswith(b"\n") or b"\r" in raw:
        raise CorpusFailure(f"{label} is not canonical newline-terminated output")
    try:
        lines = raw[:-1].decode("ascii").split("\n")
    except UnicodeError as error:
        raise CorpusFailure(f"{label} is not ASCII") from error
    if not lines or any(not line for line in lines):
        raise CorpusFailure(f"{label} contains an empty line")
    values: list[int] = []
    for line in lines:
        try:
            value = int(line, 10)
        except ValueError as error:
            raise CorpusFailure(f"{label} contains a non-integer line") from error
        if str(value) != line or value < -(2**31) or value >= 2**31:
            raise CorpusFailure(f"{label} contains a non-canonical i32 value")
        values.append(value)
    return values


def _parse_text(raw: bytes, label: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeError as error:
        raise CorpusFailure(f"{label} is not UTF-8") from error


def _canonical_line(raw: bytes, label: str) -> str:
    if not raw or len(raw) > MAX_WITNESS_BYTES or not raw.endswith(b"\n"):
        raise CorpusFailure(f"{label} is not one bounded canonical line")
    if b"\n" in raw[:-1] or b"\r" in raw:
        raise CorpusFailure(f"{label} is not one bounded canonical line")
    try:
        return raw[:-1].decode("ascii")
    except UnicodeError as error:
        raise CorpusFailure(f"{label} is not ASCII") from error


def _derive_process_observation(
    raw: bytes,
    *,
    spec: CaseSpec,
    role: str,
    stdout: bytes,
    stderr: bytes,
    checkpoint: bytes | None,
) -> int:
    value = _parse_canonical_json(raw, f"{spec.case_id} {role} process observation")
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "case_id",
        "role",
        "exit_status",
        "stdout",
        "stderr",
        "checkpoint",
    }:
        raise CorpusFailure(f"{spec.case_id} {role} process observation has wrong fields")
    expected_checkpoint = None if checkpoint is None else bytes_identity(checkpoint)
    if (
        value["schema"] != PROCESS_OBSERVATION_SCHEMA
        or value["case_id"] != spec.case_id
        or value["role"] != role
        or not isinstance(value["exit_status"], int)
        or isinstance(value["exit_status"], bool)
        or value["exit_status"] != 0
        or value["stdout"] != bytes_identity(stdout)
        or value["stderr"] != bytes_identity(stderr)
        or value["checkpoint"] != expected_checkpoint
    ):
        raise CorpusFailure(f"{spec.case_id} {role} process observation diverged")
    return value["exit_status"]


def _derive_witness(
    witness: Mapping[str, object],
    spec: CaseSpec,
    artifact_root: Path,
    budget: ARTIFACTS.ReadBudget,
    *,
    image_id: str,
    checkpoint_identity: Mapping[str, object],
) -> dict[str, object]:
    raw = {
        role: _read_reference(
            artifact_root,
            witness[role],
            f"{spec.case_id} {role}",
            budget=budget,
            max_bytes=(
                MAX_CAUSAL_EVENTS_BYTES if role == "causal_events" else MAX_WITNESS_BYTES
            ),
        )
        for role in WITNESS_FILE_NAMES
    }
    entered = _canonical_line(raw["import_entered"], "post-import entered witness")
    signal = _canonical_line(raw["signal_dispatch"], "signal dispatch result")
    release = _canonical_line(raw["release_gate"], "post-import release gate")
    observed = _canonical_line(
        raw["import_release_observed"], "post-import release observation"
    )
    container_id = _canonical_line(
        raw["container_identity"], "checkpoint container identity"
    )
    match = re.fullmatch(r"entered ([0-9a-f]{64})", entered)
    if match is None:
        raise CorpusFailure("post-import entered witness has the wrong form")
    nonce = match.group(1)
    expected_nonce = expected_post_import_nonce(image_id, spec)
    if nonce != expected_nonce:
        raise CorpusFailure("post-import witness nonce is not derived from the image and case")
    if release != f"signal-dispatched {nonce}":
        raise CorpusFailure("post-import release is detached from the entered nonce")
    if observed != f"release-observed {nonce}":
        raise CorpusFailure("post-import host did not acknowledge the release nonce")
    if re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
        raise CorpusFailure("post-import container identity is invalid")
    if signal != container_id:
        raise CorpusFailure("SIGUSR1 was not dispatched to the checkpoint container")

    event_raw = raw["causal_events"]
    if not event_raw.endswith(b"\n") or b"\r" in event_raw:
        raise CorpusFailure("post-import causal event trace is not canonical JSONL")
    event_lines = event_raw[:-1].split(b"\n")
    if len(event_lines) != len(POST_IMPORT_CAUSAL_ORDER) or any(
        not line for line in event_lines
    ):
        raise CorpusFailure("post-import causal event trace has the wrong event count")
    checkpoint_sha = checkpoint_identity.get("sha256")
    events: list[dict[str, object]] = []
    event_fields = {
        "sequence",
        "event",
        "case_id",
        "image_id",
        "nonce",
        "container_id",
        "checkpoint_sha256",
    }
    for index, (line, expected_event) in enumerate(
        zip(event_lines, POST_IMPORT_CAUSAL_ORDER, strict=True), start=1
    ):
        event = _parse_canonical_json(
            line + b"\n", f"{spec.case_id} causal event {index}"
        )
        if not isinstance(event, dict) or set(event) != event_fields:
            raise CorpusFailure(f"{spec.case_id} causal event {index} has wrong fields")
        expected_checkpoint = checkpoint_sha if index == len(event_lines) else None
        if (
            event["sequence"] != index
            or event["event"] != expected_event
            or event["case_id"] != spec.case_id
            or event["image_id"] != image_id
            or event["nonce"] != nonce
            or event["container_id"] != container_id
            or event["checkpoint_sha256"] != expected_checkpoint
        ):
            raise CorpusFailure(f"{spec.case_id} causal event {index} diverged")
        events.append(event)
    return {
        "schema": POST_IMPORT_WITNESS_SCHEMA,
        "protocol": "nonce-gated-hostcall-v1",
        "signal": "SIGUSR1",
        "nonce": nonce,
        "container_id": container_id,
        "causal_order": [event["event"] for event in events],
        "event_trace": bytes_identity(event_raw),
    }


def _derive_case(
    case: Mapping[str, object],
    spec: CaseSpec,
    artifact_root: Path,
    budget: ARTIFACTS.ReadBudget,
    *,
    image_id: str,
) -> dict[str, object]:
    artifacts = case["artifacts"]
    assert isinstance(artifacts, dict)
    streams = {
        role: _read_reference(
            artifact_root,
            artifacts[role],
            f"{spec.case_id} {role.replace('_', ' ')}",
            budget=budget,
            max_bytes=(MAX_STDERR_BYTES if role.endswith("stderr") else MAX_STDOUT_BYTES),
        )
        for role in CASE_FILE_NAMES
        if role != "checkpoint"
    }
    control = _parse_values(streams["control_stdout"], f"{spec.case_id} control stdout")
    prefix = _parse_values(
        streams["checkpoint_stdout"], f"{spec.case_id} checkpoint stdout"
    )
    suffix = _parse_values(streams["restore_stdout"], f"{spec.case_id} restore stdout")
    checkpoint = _read_reference(
        artifact_root,
        artifacts["checkpoint"],
        f"{spec.case_id} checkpoint",
        budget=budget,
        max_bytes=MAX_CHECKPOINT_BYTES,
    )
    try:
        DIAGNOSTICS.validate_application_stderr(
            "control", streams["control_stderr"], f"{spec.case_id} control stderr"
        )
        checkpoint_diagnostics, restore_diagnostics = (
            DIAGNOSTICS.validate_checkpoint_restore_pair(
                streams["checkpoint_stderr"],
                streams["restore_stderr"],
                spec.case_id,
            )
        )
    except DIAGNOSTICS.DiagnosticFailure as error:
        raise CorpusFailure(str(error)) from error
    envelope = derive_checkpoint_envelope(checkpoint, f"{spec.case_id} checkpoint")
    expected_control = list(spec.expected_control)
    try:
        marker_index = expected_control.index(spec.marker)
    except ValueError as error:
        raise CorpusFailure(f"{spec.case_id} specification lacks its marker") from error
    expected_prefix = expected_control[: marker_index + 1]
    expected_suffix = expected_control[marker_index + 1 :]
    if control != expected_control or prefix != expected_prefix or suffix != expected_suffix:
        raise CorpusFailure(f"fresh-process restore diverged for {spec.case_id}")
    if (
        checkpoint_diagnostics["exact_stackmap_records"] != spec.frames
        or restore_diagnostics["restored_frames"] != spec.frames
        or restore_diagnostics["restored_values"] != spec.typed_stack_values
        or envelope["frame_count"] != spec.frames
        or envelope["stack_value_count"] != spec.typed_stack_values
        or envelope["stack_types"] != list(spec.expected_stack_types)
        or envelope["local_types_present"] != list(spec.required_local_types)
        or envelope["memory_pages"] != restore_diagnostics["memory_pages"]
    ):
        raise CorpusFailure(f"typed checkpoint envelope diverged for {spec.case_id}")
    if spec.profile == "indirect" and 999 in control:
        raise CorpusFailure("indirect restore selected the wrong table target")

    checkpoint_identity = bytes_identity(checkpoint)
    role_inputs = {
        "control": ("control_process", "control_stdout", "control_stderr", None),
        "checkpoint": (
            "checkpoint_process",
            "checkpoint_stdout",
            "checkpoint_stderr",
            checkpoint,
        ),
        "restore": (
            "restore_process",
            "restore_stdout",
            "restore_stderr",
            checkpoint,
        ),
    }
    process_exit_statuses: dict[str, int] = {}
    for role, (process_key, stdout_key, stderr_key, process_checkpoint) in role_inputs.items():
        process_raw = _read_reference(
            artifact_root,
            artifacts[process_key],
            f"{spec.case_id} {role} process observation",
            budget=budget,
            max_bytes=MAX_PROCESS_OBSERVATION_BYTES,
        )
        process_exit_statuses[role] = _derive_process_observation(
            process_raw,
            spec=spec,
            role=role,
            stdout=streams[stdout_key],
            stderr=streams[stderr_key],
            checkpoint=process_checkpoint,
        )

    witness_raw = artifacts["post_import_witness"]
    witness = None
    if spec.profile == POST_IMPORT_PROFILE:
        assert isinstance(witness_raw, dict)
        witness = _derive_witness(
            witness_raw,
            spec,
            artifact_root,
            budget,
            image_id=image_id,
            checkpoint_identity=checkpoint_identity,
        )
    return {
        "case_id": spec.case_id,
        "profile": spec.profile,
        "optimization": spec.optimization,
        "checkpoint_marker": spec.marker,
        "expected_frames": spec.frames,
        "observed_frames": restore_diagnostics["restored_frames"],
        "expected_typed_stack_values": spec.typed_stack_values,
        "observed_typed_stack_values": restore_diagnostics["restored_values"],
        "exact_stackmap_records": checkpoint_diagnostics["exact_stackmap_records"],
        "control_values": control,
        "checkpoint_prefix_values": prefix,
        "restored_suffix_values": suffix,
        "process_exit_statuses": process_exit_statuses,
        "checkpoint_envelope": envelope,
        "post_import_signal_witness": witness,
    }


def validate_receipt(
    receipt: object,
    *,
    artifact_root: Path,
    expected_source_lock: Path = DEFAULT_SOURCE_LOCK,
) -> dict[str, object]:
    validate_receipt_structure(receipt)
    assert isinstance(receipt, dict)
    budget = ARTIFACTS.ReadBudget(MAX_RETAINED_BYTES)
    source_lock_raw = _read_reference(
        artifact_root,
        receipt["wanco_source_lock"],
        "Wanco source lock",
        budget=budget,
        max_bytes=MAX_SOURCE_LOCK_BYTES,
    )
    try:
        expected_source_lock_raw = ARTIFACTS.read_bounded_file(
            expected_source_lock.absolute(),
            "expected Wanco source lock",
            max_bytes=MAX_SOURCE_LOCK_BYTES,
        )
    except ARTIFACTS.ArtifactError as error:
        raise CorpusFailure(str(error)) from error
    if source_lock_raw != expected_source_lock_raw:
        raise CorpusFailure("retained Wanco source lock differs from the expected repository lock")
    build_raw = _read_reference(
        artifact_root,
        receipt["wanco_build_receipt"],
        "Wanco build receipt",
        budget=budget,
        max_bytes=MAX_BUILD_RECEIPT_BYTES,
    )
    _validate_build_receipt(
        build_raw,
        source_lock_raw=source_lock_raw,
        receipt=receipt,
    )
    cases = receipt["cases"]
    assert isinstance(cases, list)
    derived = [
        _derive_case(
            case,
            spec,
            artifact_root,
            budget,
            image_id=receipt["image_id"],
        )
        for case, spec in zip(cases, CASE_SPECS, strict=True)
        if isinstance(case, dict)
    ]
    if len(derived) != len(CASE_SPECS):
        raise CorpusFailure("typed corpus case representation is invalid")
    qualification = {
        "schema": QUALIFICATION_SCHEMA,
        "manifest": bytes_identity(canonical_bytes(receipt) + b"\n"),
        "image_tag": receipt["image_tag"],
        "image_id": receipt["image_id"],
        "wanco_source_lock": reference_identity(
            receipt["wanco_source_lock"], "Wanco source lock"
        ),
        "wanco_build_receipt": reference_identity(
            receipt["wanco_build_receipt"], "Wanco build receipt"
        ),
        "cases": derived,
    }
    validate_qualification_structure(qualification)
    return qualification


def _validate_qualification_identity(value: object, label: str) -> None:
    if not isinstance(value, dict) or set(value) != {"sha256", "size"}:
        raise CorpusFailure(f"{label} identity is malformed")
    try:
        ARTIFACTS.validate_reference({"path": "bound-input", **value}, label)
    except ARTIFACTS.ArtifactError as error:
        raise CorpusFailure(str(error)) from error


def validate_qualification_structure(value: object) -> None:
    """Validate a derived summary's shape; acceptance still requires raw evidence."""
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "manifest",
        "image_tag",
        "image_id",
        "wanco_source_lock",
        "wanco_build_receipt",
        "cases",
    }:
        raise CorpusFailure("typed corpus qualification has the wrong fields")
    if value["schema"] != QUALIFICATION_SCHEMA:
        raise CorpusFailure("unsupported typed corpus qualification schema")
    _validate_qualification_identity(value["manifest"], "qualification manifest")
    _validate_qualification_identity(
        value["wanco_source_lock"], "qualification source lock"
    )
    _validate_qualification_identity(
        value["wanco_build_receipt"], "qualification build receipt"
    )
    if not isinstance(value["image_tag"], str) or not value["image_tag"]:
        raise CorpusFailure("typed corpus qualification image tag is empty")
    if (
        not isinstance(value["image_id"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", value["image_id"]) is None
    ):
        raise CorpusFailure("typed corpus qualification image identity is invalid")
    cases = value["cases"]
    if not isinstance(cases, list) or len(cases) != len(CASE_SPECS):
        raise CorpusFailure("typed corpus qualification must contain twelve cases")
    fields = {
        "case_id",
        "profile",
        "optimization",
        "checkpoint_marker",
        "expected_frames",
        "observed_frames",
        "expected_typed_stack_values",
        "observed_typed_stack_values",
        "exact_stackmap_records",
        "control_values",
        "checkpoint_prefix_values",
        "restored_suffix_values",
        "process_exit_statuses",
        "checkpoint_envelope",
        "post_import_signal_witness",
    }
    envelope_fields = {
        "schema",
        "sha256",
        "size",
        "frame_count",
        "local_value_count",
        "local_types_present",
        "stack_value_count",
        "stack_types",
        "memory_pages",
        "memory_encoding",
        "compressed_memory_bytes",
    }
    for case, spec in zip(cases, CASE_SPECS, strict=True):
        if not isinstance(case, dict) or set(case) != fields:
            raise CorpusFailure(f"qualification case {spec.case_id} has wrong fields")
        if (
            case["case_id"] != spec.case_id
            or case["profile"] != spec.profile
            or case["optimization"] != spec.optimization
            or case["checkpoint_marker"] != spec.marker
            or case["expected_frames"] != spec.frames
            or case["observed_frames"] != spec.frames
            or case["expected_typed_stack_values"] != spec.typed_stack_values
            or case["observed_typed_stack_values"] != spec.typed_stack_values
            or case["exact_stackmap_records"] != spec.frames
            or case["control_values"] != list(spec.expected_control)
            or case["process_exit_statuses"]
            != {"control": 0, "checkpoint": 0, "restore": 0}
        ):
            raise CorpusFailure(f"qualification case {spec.case_id} changed its contract")
        marker_index = list(spec.expected_control).index(spec.marker)
        if (
            case["checkpoint_prefix_values"]
            != list(spec.expected_control[: marker_index + 1])
            or case["restored_suffix_values"]
            != list(spec.expected_control[marker_index + 1 :])
        ):
            raise CorpusFailure(f"qualification case {spec.case_id} output diverged")
        envelope = case["checkpoint_envelope"]
        if not isinstance(envelope, dict) or set(envelope) != envelope_fields:
            raise CorpusFailure(f"qualification case {spec.case_id} envelope is malformed")
        _validate_qualification_identity(
            {"sha256": envelope.get("sha256"), "size": envelope.get("size")},
            f"qualification case {spec.case_id} checkpoint",
        )
        if (
            envelope["schema"] != CHECKPOINT_ENVELOPE_SCHEMA
            or envelope["frame_count"] != spec.frames
            or not isinstance(envelope["local_value_count"], int)
            or isinstance(envelope["local_value_count"], bool)
            or envelope["local_value_count"] < len(spec.required_local_types)
            or envelope["local_types_present"] != list(spec.required_local_types)
            or envelope["stack_value_count"] != spec.typed_stack_values
            or envelope["stack_types"] != list(spec.expected_stack_types)
            or not isinstance(envelope["memory_pages"], int)
            or isinstance(envelope["memory_pages"], bool)
            or envelope["memory_pages"] <= 0
            or envelope["memory_encoding"] != "lz4-block-exact-length"
            or not isinstance(envelope["compressed_memory_bytes"], int)
            or isinstance(envelope["compressed_memory_bytes"], bool)
            or envelope["compressed_memory_bytes"] <= 0
        ):
            raise CorpusFailure(f"qualification case {spec.case_id} envelope changed")
        witness = case["post_import_signal_witness"]
        if spec.profile != POST_IMPORT_PROFILE:
            if witness is not None:
                raise CorpusFailure(f"qualification case {spec.case_id} has a witness")
            continue
        if not isinstance(witness, dict) or set(witness) != {
            "schema",
            "protocol",
            "signal",
            "nonce",
            "container_id",
            "causal_order",
            "event_trace",
        }:
            raise CorpusFailure(f"qualification case {spec.case_id} witness is malformed")
        _validate_qualification_identity(
            witness["event_trace"], f"qualification case {spec.case_id} causal events"
        )
        if (
            witness["schema"] != POST_IMPORT_WITNESS_SCHEMA
            or witness["protocol"] != "nonce-gated-hostcall-v1"
            or witness["signal"] != "SIGUSR1"
            or witness["nonce"] != expected_post_import_nonce(value["image_id"], spec)
            or not isinstance(witness["container_id"], str)
            or re.fullmatch(r"[0-9a-f]{64}", witness["container_id"]) is None
            or witness["causal_order"] != POST_IMPORT_CAUSAL_ORDER
        ):
            raise CorpusFailure(f"qualification case {spec.case_id} witness changed")


def _publish_receipt(path: Path, receipt: Mapping[str, object]) -> None:
    raw = canonical_bytes(receipt) + b"\n"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise CorpusFailure(f"refusing to replace typed corpus receipt: {path}") from error
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _publish_source(
    source: Path, artifact_root: Path, relative: str
) -> dict[str, object]:
    try:
        return ARTIFACTS.publish_reference(source, artifact_root, relative)
    except ARTIFACTS.ArtifactError as error:
        raise CorpusFailure(str(error)) from error


def build_bundle(
    *,
    source_root: Path,
    artifact_root: Path,
    image_tag: str,
    image_id: str,
    wanco_source_lock: Path,
    wanco_build_receipt: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    if artifact_root.exists() or artifact_root.is_symlink():
        raise CorpusFailure(f"refusing to reuse typed corpus artifact root: {artifact_root}")
    artifact_root.mkdir(mode=0o700)
    source_lock_reference = _publish_source(
        wanco_source_lock,
        artifact_root,
        "inputs/wanco-source-lock.json",
    )
    build_reference = _publish_source(
        wanco_build_receipt,
        artifact_root,
        "inputs/wanco-build-receipt.json",
    )
    cases: list[dict[str, object]] = []
    for spec in CASE_SPECS:
        case_source = source_root / "results" / spec.case_id
        artifacts = {
            role: _publish_source(
                case_source / name,
                artifact_root,
                _case_relative(spec, name),
            )
            for role, name in CASE_FILE_NAMES.items()
        }
        artifacts.update(
            {
                role: _publish_source(
                    case_source / name,
                    artifact_root,
                    _case_relative(spec, name),
                )
                for role, name in PROCESS_FILE_NAMES.items()
            }
        )
        witness = None
        if spec.profile == POST_IMPORT_PROFILE:
            witness = {
                role: _publish_source(
                    case_source / name,
                    artifact_root,
                    _case_relative(spec, name),
                )
                for role, name in WITNESS_FILE_NAMES.items()
            }
        artifacts["post_import_witness"] = witness
        cases.append(
            {
                "case_id": spec.case_id,
                "profile": spec.profile,
                "optimization": spec.optimization,
                "artifacts": artifacts,
            }
        )
    receipt = {
        "schema": SCHEMA,
        "image_tag": image_tag,
        "image_id": image_id,
        "wanco_source_lock": source_lock_reference,
        "wanco_build_receipt": build_reference,
        "cases": cases,
    }
    qualification = validate_receipt(
        receipt,
        artifact_root=artifact_root,
        expected_source_lock=wanco_source_lock,
    )
    _publish_receipt(artifact_root / "receipt.json", receipt)
    return receipt, qualification


def load_and_validate(
    path: Path, *, expected_source_lock: Path = DEFAULT_SOURCE_LOCK
) -> tuple[dict[str, object], dict[str, object]]:
    absolute = path.absolute()
    try:
        raw = ARTIFACTS.read_bounded_file(
            absolute, "typed corpus receipt", max_bytes=MAX_RECEIPT_BYTES
        )
    except ARTIFACTS.ArtifactError as error:
        raise CorpusFailure(str(error)) from error
    try:
        receipt = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CorpusFailure(f"typed corpus receipt is invalid JSON: {error}") from error
    if canonical_bytes(receipt) + b"\n" != raw:
        raise CorpusFailure("typed corpus receipt is not canonical JSON")
    if not isinstance(receipt, dict):
        raise CorpusFailure("typed corpus receipt is not an object")
    qualification = validate_receipt(
        receipt,
        artifact_root=absolute.parent,
        expected_source_lock=expected_source_lock,
    )
    return receipt, qualification


def retain_bundle(
    source_receipt: Path,
    destination_root: Path,
    *,
    expected_source_lock: Path = DEFAULT_SOURCE_LOCK,
) -> tuple[dict[str, object], dict[str, object]]:
    receipt, qualification = load_and_validate(
        source_receipt, expected_source_lock=expected_source_lock
    )
    if destination_root.exists() or destination_root.is_symlink():
        raise CorpusFailure(
            f"refusing to reuse retained typed corpus root: {destination_root}"
        )
    destination_root.mkdir(mode=0o700)
    source_root = source_receipt.absolute().parent
    for reference in iter_references(receipt):
        relative = reference["path"]
        assert isinstance(relative, str)
        published = _publish_source(
            source_root.joinpath(*relative.split("/")), destination_root, relative
        )
        if published != reference:
            raise CorpusFailure(f"retained typed corpus changed while copying: {relative}")
    _publish_receipt(destination_root / "receipt.json", receipt)
    copied_receipt, copied_qualification = load_and_validate(
        destination_root / "receipt.json",
        expected_source_lock=expected_source_lock,
    )
    if copied_receipt != receipt or copied_qualification != qualification:
        raise CorpusFailure("retained typed corpus differs after relocation")
    return copied_receipt, copied_qualification


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--source-root", required=True, type=Path)
    build.add_argument("--artifact-root", required=True, type=Path)
    build.add_argument("--image-tag", required=True)
    build.add_argument("--image-id", required=True)
    build.add_argument("--wanco-source-lock", required=True, type=Path)
    build.add_argument("--wanco-build-receipt", required=True, type=Path)
    validate = subparsers.add_parser("validate")
    validate.add_argument("receipt", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        if arguments.command == "build":
            _, qualification = build_bundle(
                source_root=arguments.source_root,
                artifact_root=arguments.artifact_root,
                image_tag=arguments.image_tag,
                image_id=arguments.image_id,
                wanco_source_lock=arguments.wanco_source_lock,
                wanco_build_receipt=arguments.wanco_build_receipt,
            )
            print(
                "Wanco typed corpus artifact: "
                f"{arguments.artifact_root / 'receipt.json'} "
                f"({len(qualification['cases'])} cases)"
            )
        else:
            _, qualification = load_and_validate(arguments.receipt)
            print(
                "Wanco typed corpus raw evidence is valid: "
                f"{arguments.receipt} ({len(qualification['cases'])} cases)"
            )
    except (CorpusFailure, OSError) as error:
        print(f"Wanco typed corpus evidence failed: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
