#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/wacogo-materialize-module-cache.sh

Validates an existing offline Wacogo module cache or materializes one from the
Docker image's verified cache seed. The paths are supplied through:
  VISA_WACOGO_GOMODCACHE
  VISA_WACOGO_GOMODCACHE_SEED
EOF
}

fail() {
    printf 'Wacogo module-cache preparation failed: %s\n' "$*" >&2
    exit 1
}

if [[ "$#" -ne 0 ]]; then
    usage
    exit 64
fi

module_cache=${VISA_WACOGO_GOMODCACHE:-}
cache_seed=${VISA_WACOGO_GOMODCACHE_SEED:-}
[[ -n "$module_cache" ]] || fail 'VISA_WACOGO_GOMODCACHE is required'

if [[ -e "$module_cache" || -L "$module_cache" ]]; then
    [[ -d "$module_cache" && ! -L "$module_cache" ]] \
        || fail "module cache is not a non-symlink directory: $module_cache"
else
    [[ -n "$cache_seed" ]] || fail 'missing module cache and VISA_WACOGO_GOMODCACHE_SEED'
    [[ -f "$cache_seed" && ! -L "$cache_seed" ]] \
        || fail "cache seed is not a regular non-symlink file: $cache_seed"
    mkdir -m 0700 -p -- "$module_cache"
    PYTHONDONTWRITEBYTECODE=1 python3 - "$cache_seed" <<'PY'
from pathlib import Path, PurePosixPath
import sys
import tarfile

archive = Path(sys.argv[1])
with tarfile.open(archive, mode="r:gz") as source:
    members = source.getmembers()
    if not members:
        raise SystemExit("module-cache seed is empty")
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise SystemExit(f"unsafe module-cache seed path: {member.name}")
        if member.issym() or member.islnk() or member.isdev():
            raise SystemExit(f"unsupported module-cache seed member: {member.name}")
PY
    tar --extract --gzip --file "$cache_seed" --directory "$module_cache"
    printf 'wacogo-module-cache-seed=%s sha256=%s\n' \
        "$cache_seed" "$(sha256sum "$cache_seed" | cut -d' ' -f1)"
fi

for required in \
    github.com/regclient/regclient@v0.8.3/testdata/.wh.layer2.txt \
    github.com/regclient/regclient@v0.8.3/testdata/exdir/.wh..wh..opq; do
    [[ -f "$module_cache/$required" && ! -L "$module_cache/$required" ]] \
        || fail "module cache omits required regular file: $required"
done

printf 'wacogo-module-cache=%s status=ready\n' \
    "$(CDPATH='' cd -- "$module_cache" && pwd -P)"
