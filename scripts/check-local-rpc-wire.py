#!/usr/bin/env python3
"""Fail-closed static policy checks for the three vISA local RPC wire families."""

from __future__ import annotations

import ast
from pathlib import Path
import re
import sys
import tomllib


ROOT = Path(__file__).resolve().parent.parent
WIRE_ROOT = ROOT / "crates/core/visa_local_rpc/src"
FAMILY_MODULE_NAMES = frozenset({"agent_control", "ownership", "nexus_adapter"})
FAMILY_MODULES = {
    "agent_control": WIRE_ROOT / "agent_control.rs",
    "ownership": WIRE_ROOT / "ownership.rs",
    "nexus_adapter": WIRE_ROOT / "nexus_adapter.rs",
}
NON_WIRE_MODULE_NAMES = frozenset({"lib", "codec", "schema"})

FORBIDDEN_SOURCE_PATTERNS = {
    r"\bHashMap\b": "unordered HashMap",
    r"\bHashSet\b": "unordered HashSet",
    r"\bf32\b": "f32",
    r"\bf64\b": "f64",
}
SERDE_ATTRIBUTE_PATTERN = re.compile(r"#\s*\[\s*serde\b")
DERIVE_ATTRIBUTE_PATTERN = re.compile(r"#\s*\[\s*derive\s*\(.*?\)\s*\]", re.DOTALL)
SERDE_SURFACE_PATTERN = re.compile(r"\b(?:serde|Serialize|Deserialize)\b")
ALLOWED_SERDE_IMPORT = "use serde::{Deserialize, Serialize};"
TRAIT_IMPL_HEADER_PATTERN = re.compile(
    r"^\s*(impl\b[^{};]*?\bfor\b[^{};]*?)\{",
    re.MULTILINE | re.DOTALL,
)
PLATFORM_INTEGER_PATTERN = re.compile(r"\b(?:usize|isize)\b")
PLATFORM_INTEGER_CONST_PATTERN = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?const\s+\w+\s*:\s*(?:usize|isize)\s*=\s*[^;]+;\s*$",
    re.MULTILINE,
)


class LocalRpcWireError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LocalRpcWireError(message)


def load_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def discover_wire_modules(root: Path = ROOT) -> dict[str, Path]:
    wire_root = root / WIRE_ROOT.relative_to(ROOT)
    modules: dict[str, Path] = {}
    for path in sorted(wire_root.rglob("*.rs")):
        relative = path.relative_to(wire_root)
        if len(relative.parts) == 1 and path.stem in NON_WIRE_MODULE_NAMES:
            continue
        module = relative.with_suffix("").as_posix()
        require(module not in modules, f"duplicate local RPC wire module {module}")
        modules[module] = path
    require(
        FAMILY_MODULE_NAMES <= set(modules),
        "local RPC repository is missing one or more independent family modules",
    )
    return modules


def check_wire_module_policy(module: str, source: str) -> None:
    for pattern, label in FORBIDDEN_SOURCE_PATTERNS.items():
        require(
            re.search(pattern, source) is None,
            f"{module} wire source contains forbidden {label}",
        )

    require(
        SERDE_ATTRIBUTE_PATTERN.search(source) is None,
        (
            f"{module} wire source contains unsupported serde attribute; "
            "production wire modules permit no #[serde(...)] shape attributes"
        ),
    )

    for match in TRAIT_IMPL_HEADER_PATTERN.finditer(source):
        header = " ".join(match.group(1).split())
        require(
            header.startswith("impl WireValidation for "),
            (
                f"{module} wire source contains forbidden manual trait implementation; "
                "only the local WireValidation trait may be implemented manually"
            ),
        )

    allowed_import_count = source.count(ALLOWED_SERDE_IMPORT)
    require(
        allowed_import_count <= 1,
        f"{module} wire source contains duplicate Serde derive imports",
    )
    serde_outside_derives = source.replace(ALLOWED_SERDE_IMPORT, "")
    serde_outside_derives = DERIVE_ATTRIBUTE_PATTERN.sub("", serde_outside_derives)
    require(
        SERDE_SURFACE_PATTERN.search(serde_outside_derives) is None,
        (
            f"{module} wire source contains unsupported Serde surface; "
            "only the exact derive import and derive attributes are permitted"
        ),
    )

    source_without_sized_constants = PLATFORM_INTEGER_CONST_PATTERN.sub("", source)
    require(
        PLATFORM_INTEGER_PATTERN.search(source_without_sized_constants) is None,
        f"{module} wire source contains forbidden usize/isize wire type",
    )


def check_dependencies(root: Path = ROOT) -> None:
    workspace = load_toml(root / "Cargo.toml")["workspace"]["dependencies"]
    require(
        workspace.get("postcard")
        == {
            "version": "=1.1.3",
            "default-features": False,
            "features": ["alloc"],
        },
        "workspace postcard dependency must remain exact =1.1.3 with alloc only",
    )
    require(
        workspace.get("postcard-schema")
        == {
            "version": "=0.2.5",
            "default-features": False,
            "features": ["derive", "use-std"],
        },
        "workspace postcard-schema dependency must remain exact =0.2.5 derive/use-std",
    )
    require(
        workspace.get("serde_json_canonicalizer") == "=0.3.2",
        "workspace JCS dependency must remain exact serde_json_canonicalizer =0.3.2",
    )
    require(
        workspace.get("zbus")
        == {
            "version": "=5.18.0",
            "default-features": False,
            "features": ["async-io"],
        },
        "workspace zbus dependency must remain exact =5.18.0 async-io",
    )

    core = load_toml(root / "crates/core/visa_local_rpc/Cargo.toml")
    core_dependencies = core["dependencies"]
    require(
        set(core_dependencies) == {"postcard", "postcard-schema", "serde", "sha2"},
        "visa_local_rpc must remain a pure wire crate without transport or JCS dependencies",
    )
    require(
        all(value == {"workspace": True} for value in core_dependencies.values()),
        "visa_local_rpc dependencies must resolve through the frozen workspace table",
    )

    conformance = load_toml(root / "crates/testing/visa-conformance/Cargo.toml")
    dependencies = conformance["dependencies"]
    require(
        dependencies.get("serde_json_canonicalizer") == {"workspace": True},
        "visa-conformance must own the std-only JCS implementation",
    )
    require(
        dependencies.get("visa_local_rpc")
        == {"path": "../../core/visa_local_rpc"},
        "visa-conformance must verify the production local RPC types",
    )
    require(
        dependencies.get("joint_handoff_core")
        == {"path": "../../core/joint_handoff_core"},
        "visa-conformance must check the local neutral projection against joint_handoff_core",
    )


def check_source_policy(
    family_sources: dict[str, str],
) -> None:
    require(
        set(family_sources) == set(FAMILY_MODULES),
        "local RPC family source set drifted",
    )
    family_ids: dict[str, bytes] = {}
    namespace_fields = (
        "SCHEMA",
        "REQUEST_NAMESPACE",
        "RESPONSE_NAMESPACE",
        "ERROR_NAMESPACE",
        "REPLAY_NAMESPACE",
        "GOLDEN_CORPUS_ID",
        "OWNED_SCHEMA_ARTIFACT_ID",
        "INTERFACE",
    )
    namespaces: dict[str, dict[str, str]] = {}

    for family, source in family_sources.items():
        check_wire_module_policy(family, source)
        for other_family in set(family_sources) - {family}:
            require(
                re.search(rf"\b{re.escape(other_family)}::", source) is None,
                f"{family} wire source imports sibling family {other_family}",
            )

        family_match = re.search(
            r'pub const FAMILY_ID:\s*\[u8;\s*16\]\s*=\s*\*b("(?:[^"\\]|\\.)*");',
            source,
        )
        require(family_match is not None, f"{family} FAMILY_ID literal is missing")
        family_id = ast.literal_eval("b" + family_match.group(1))
        require(len(family_id) == 16, f"{family} FAMILY_ID is not exactly 16 bytes")
        family_ids[family] = family_id

        values: dict[str, str] = {}
        for field in namespace_fields:
            match = re.search(
                rf'pub const {field}:\s*&str\s*=\s*"([^"]+)";',
                source,
            )
            require(match is not None, f"{family} {field} constant is missing")
            values[field] = match.group(1)
        namespaces[family] = values

        require(
            "pub struct ReplayRecord" in source
            and "pub fn encode_request" in source
            and "pub fn decode_request" in source
            and "pub fn encode_response_for" in source
            and "pub fn decode_response_for" in source
            and "pub fn encode_replay" in source
            and "pub fn decode_replay" in source
            and "response.validate_for(request)" in source
            and "decode_response_for(&request" in source
            and "response.validate_for(&request)" in source,
            f"{family} paired response or exact replay validation path is incomplete",
        )
        if family == "agent_control":
            require(
                "expected_role: AgentRole" in source
                and "self.server.role != expected_role" in source
                and "endpoint_role: AgentRole" in source,
                "agent-control paired response/replay must bind the verified endpoint role",
            )

    require(
        len(set(family_ids.values())) == len(family_ids),
        "local RPC serialized family IDs must remain distinct",
    )
    for field in namespace_fields:
        values = [namespaces[family][field] for family in sorted(namespaces)]
        require(
            len(set(values)) == len(values),
            f"local RPC {field} values must remain distinct",
        )


def check_repository_sources(root: Path = ROOT) -> None:
    module_paths = discover_wire_modules(root)
    module_sources = {
        module: path.read_text(encoding="utf-8") for module, path in module_paths.items()
    }
    family_sources = {
        family: module_sources[family] for family in sorted(FAMILY_MODULE_NAMES)
    }
    check_source_policy(family_sources)

    for module in sorted(set(module_sources) - FAMILY_MODULE_NAMES):
        check_wire_module_policy(module, module_sources[module])

    schema = (root / WIRE_ROOT.relative_to(ROOT) / "schema.rs").read_text(encoding="utf-8")
    require(
        "all_used_types" not in schema,
        "owned-schema production must not serialize nondeterministic HashSet discovery",
    )
    require(
        "serde_json_canonicalizer" not in schema,
        "std-only JCS must not enter the pure local RPC wire crate",
    )

    library = (root / WIRE_ROOT.relative_to(ROOT) / "lib.rs").read_text(encoding="utf-8")
    codec = (root / WIRE_ROOT.relative_to(ROOT) / "codec.rs").read_text(encoding="utf-8")
    for generic in (
        "canonical_request_bytes",
        "canonical_response_bytes",
        "decode_canonical_request",
        "decode_canonical_response",
    ):
        require(
            generic not in library,
            f"crate root must not expose unpaired generic codec helper {generic}",
        )
        require(
            re.search(rf"pub\s+fn\s+{generic}\b", codec) is None,
            f"generic codec helper {generic} must remain crate-private",
        )

    common = module_sources["common"]
    require(
        "JOINT_RECEIPT_DIGEST_DOMAIN" in common
        and "pub const fn neutral_tag" in common
        and "pub const fn payload_schema" in common
        and "joint_receipt_digest(self.reference.kind, &self.payload.bytes)" in common,
        "neutral receipt carrier kind/schema/digest self-consistency path is incomplete",
    )


def main() -> int:
    try:
        check_dependencies()
        check_repository_sources()
    except (OSError, tomllib.TOMLDecodeError, LocalRpcWireError) as error:
        print(f"local RPC wire check failed: {error}", file=sys.stderr)
        return 1
    print("local RPC wire dependency, isolation, and serde policy passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
