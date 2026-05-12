#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/build-vmos-ltp-static-syscalls.sh <ltp-source-dir> <binary-root> <manifest> [limit]

Builds LTP syscall test binaries as static ELF files in a Docker toolchain,
copies a manifest-sized candidate set into <binary-root>, and writes a VMOS LTP
manifest consumable by scripts/run-vmos-ltp-manifest.sh.

The build happens under:

  ${VMOS_LTP_BUILD_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/vmos-ltp/build-src}

This keeps large LTP artifacts out of repo target/ and avoids tmpfs exhaustion.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "$#" -lt 3 ]]; then
    usage
    exit 2
fi

source_dir="$1"
binary_root="$2"
manifest="$3"
limit="${4:-500}"
cache_root="${XDG_CACHE_HOME:-$HOME/.cache}/vmos-ltp"
build_dir="${VMOS_LTP_BUILD_DIR:-$cache_root/build-src}"

case "$limit" in
    ''|*[!0-9]*)
        echo "limit must be a positive integer" >&2
        exit 64
        ;;
esac
if [[ "$limit" -lt 1 ]]; then
    echo "limit must be >= 1" >&2
    exit 64
fi
if [[ ! -d "$source_dir" ]]; then
    echo "LTP source directory not found: $source_dir" >&2
    exit 66
fi
if [[ ! -f "$source_dir/configure" || ! -f "$source_dir/runtest/syscalls" ]]; then
    echo "LTP source directory does not look like an upstream LTP checkout: $source_dir" >&2
    exit 66
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required for the static LTP build toolchain" >&2
    exit 69
fi

mkdir -p "$cache_root" "$(dirname "$manifest")"
rm -rf "$build_dir" "$binary_root"
mkdir -p "$build_dir" "$binary_root"

tar -C "$source_dir" --exclude=.git -cf - . | tar -C "$build_dir" -xf -

docker run --rm -v "$build_dir:/src" -w /src debian:stable-slim bash -lc '
    set -euo pipefail
    apt-get update >/dev/null
    apt-get install -y --no-install-recommends \
        build-essential make pkgconf autoconf automake bison flex m4 \
        linux-libc-dev libc6-dev ca-certificates >/dev/null
    ./configure CFLAGS="-O2 -D_GNU_SOURCE" LDFLAGS="-static" >/src/vmos-ltp-configure.log
    make -k -j"$(nproc)" -C testcases/kernel/syscalls
'
docker run --rm -v "$build_dir:/src" debian:stable-slim \
    chown -R "$(id -u):$(id -g)" /src >/dev/null 2>&1 || true

python3 - "$build_dir" "$binary_root" "$manifest" "$limit" <<'PY'
from pathlib import Path
import shutil
import stat
import sys

src = Path(sys.argv[1])
binary_root = Path(sys.argv[2])
manifest = Path(sys.argv[3])
limit = int(sys.argv[4])
syscalls = src / "testcases/kernel/syscalls"
runtest = src / "runtest/syscalls"
binary_root.mkdir(parents=True, exist_ok=True)
manifest.parent.mkdir(parents=True, exist_ok=True)

index = {}
for path in syscalls.rglob("*"):
    try:
        mode = path.stat().st_mode
    except OSError:
        continue
    if not path.is_file() or not (mode & stat.S_IXUSR):
        continue
    try:
        with path.open("rb") as f:
            if f.read(4) != b"\x7fELF":
                continue
    except OSError:
        continue
    index.setdefault(path.name, []).append(path)

rows = []
seen = set()
for raw in runtest.read_text(errors="ignore").splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    parts = line.split()
    if len(parts) < 2:
        continue
    case_id, command = parts[0], parts[1]
    if case_id in seen or "/" in command or len(parts) != 2:
        continue
    candidates = index.get(command) or index.get(case_id)
    if not candidates:
        continue
    chosen = None
    for candidate in candidates:
        if case_id.startswith(candidate.parent.name):
            chosen = candidate
            break
    chosen = chosen or candidates[0]
    rows.append((case_id, chosen))
    seen.add(case_id)
    if len(rows) >= limit:
        break

if len(rows) < limit:
    for name in sorted(index):
        if name in seen or name.endswith(".so"):
            continue
        rows.append((name, index[name][0]))
        seen.add(name)
        if len(rows) >= limit:
            break

if len(rows) < limit:
    raise SystemExit(f"only found {len(rows)} static LTP ELF candidates, requested {limit}")

with manifest.open("w") as out:
    out.write("# spec_id\tcase_id\trelative_binary\tsource\n")
    for case_id, source in rows:
        destination = binary_root / case_id
        if destination.exists():
            destination.unlink()
        shutil.copy2(source, destination)
        destination.chmod(destination.stat().st_mode | stat.S_IXUSR)
        out.write(
            f"linux-ltp.syscalls.core\t{case_id}\t{destination.name}\t{source.relative_to(src)}\n"
        )

print(f"indexed_elf={sum(len(v) for v in index.values())}")
print(f"planned={len(rows)}")
print(f"manifest={manifest}")
print(f"binary_root={binary_root}")
PY
