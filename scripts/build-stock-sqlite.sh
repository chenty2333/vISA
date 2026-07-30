#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

if [[ $(uname -m) != x86_64 ]]; then
    printf '%s\n' 'the stock-SQLite Wanco build requires an x86_64 host' >&2
    exit 1
fi
if [[ -n ${VISA_SQLITE_WANCO_OPTIMIZATION:-} ]]; then
    printf '%s\n' 'VISA_SQLITE_WANCO_OPTIMIZATION is forbidden; the source lock selects -O1' >&2
    exit 1
fi

read_lock() {
    python3 - "$1" <<'PY'
import json
import sys

with open("third_party/sqlite/source-lock.json", encoding="utf-8") as source:
    value = json.load(source)
for component in sys.argv[1].split("."):
    if isinstance(value, list):
        value = value[int(component)]
    else:
        value = value[component]
if not isinstance(value, (str, int)):
    raise SystemExit(f"source-lock path is not scalar: {sys.argv[1]}")
print(value)
PY
}

python3 scripts/check-sqlite-source.py
python3 scripts/check-wanco-carrier-source.py

version=$(read_lock upstream.version)
archive_url=$(read_lock upstream.archive.url)
archive_sha256=$(read_lock upstream.archive.sha256)
archive_size=$(read_lock upstream.archive.size)
wasi_libc_version=$(read_lock wasi_build.packages.0.version)
wasi_libc_sha=$(read_lock wasi_build.packages.0.sha256)
clang_rt_version=$(read_lock wasi_build.packages.1.version)
clang_rt_sha=$(read_lock wasi_build.packages.1.sha256)
compiler_optimization=$(read_lock wasi_build.optimization)
carrier_optimization=$(read_lock carrier_build.optimization)
expected_wanco_revision=$(read_lock carrier_build.wanco_revision)
lock_sha=$(sha256sum third_party/sqlite/source-lock.json | cut -d' ' -f1)
cache_root="$repo_root/target/.ci-cache/stock-sqlite"
mkdir -p "$cache_root"

wanco_receipt="$repo_root/target/.ci-cache/wanco-carrier/build-receipt.json"
expected_patch_set=$(
    python3 - <<'PY'
import hashlib
import json

with open("third_party/wanco/source-lock.json", encoding="utf-8") as source:
    patches = json.load(source)["patches"]
print(hashlib.sha256("".join(item["sha256"] for item in patches).encode()).hexdigest())
PY
)
reuse_wanco=false
if [[ -f $wanco_receipt ]]; then
    read -r candidate_image candidate_revision candidate_patch_set < <(
        python3 - "$wanco_receipt" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    receipt = json.load(source)
print(
    receipt.get("image_tag", ""),
    receipt.get("revision", ""),
    receipt.get("patch_set_sha256", ""),
)
PY
    )
    if [[ -n $candidate_image &&
        $candidate_revision == "$expected_wanco_revision" &&
        $candidate_patch_set == "$expected_patch_set" ]] &&
        docker image inspect "$candidate_image" >/dev/null 2>&1
    then
        reuse_wanco=true
    fi
fi
if [[ $reuse_wanco != true ]]; then
    scripts/build-wanco-carrier.sh
fi

read -r wanco_image wanco_revision wanco_compiler_sha wanco_runtime_sha < <(
    python3 - "$wanco_receipt" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    receipt = json.load(source)
print(
    receipt["image_tag"],
    receipt["revision"],
    receipt["wanco_binary_sha256"],
    receipt["runtime_staticlib_sha256"],
)
PY
)
if [[ $wanco_revision != "$expected_wanco_revision" ]]; then
    printf 'Wanco revision mismatch: %s != %s\n' "$wanco_revision" "$expected_wanco_revision" >&2
    exit 1
fi
wanco_image_id=$(docker image inspect --format '{{.Id}}' "$wanco_image")
wanco_source_lock_sha=$(sha256sum third_party/wanco/source-lock.json | cut -d' ' -f1)
wanco_receipt_sha=$(sha256sum "$wanco_receipt" | cut -d' ' -f1)

archive="$cache_root/sqlite-amalgamation-3530400.zip"
if [[ ! -f $archive ]]; then
    download=$(mktemp "$cache_root/.sqlite-download.XXXXXXXX")
    cleanup_download() {
        if [[ -f $download ]]; then
            find "$download" -xdev -delete
        fi
    }
    trap cleanup_download EXIT
    curl --fail --location --proto '=https' --tlsv1.2 --output "$download" "$archive_url"
    python3 scripts/check-sqlite-source.py --archive "$download"
    if [[ $(stat -c %s "$download") != "$archive_size" ]] ||
        [[ $(sha256sum "$download" | cut -d' ' -f1) != "$archive_sha256" ]]
    then
        printf '%s\n' 'downloaded SQLite archive identity differs from the source lock' >&2
        exit 1
    fi
    mv "$download" "$archive"
    trap - EXIT
fi
python3 scripts/check-sqlite-source.py --archive "$archive"

build_image="visa-stock-sqlite-build:3530400-${lock_sha:0:12}-${expected_patch_set:0:12}"
docker build --progress=plain \
    --provenance=false \
    --build-arg "WANCO_BASE=$wanco_image" \
    --build-arg "WASI_LIBC_VERSION=$wasi_libc_version" \
    --build-arg "WASI_LIBC_SHA256=$wasi_libc_sha" \
    --build-arg "CLANG_RT_WASM32_VERSION=$clang_rt_version" \
    --build-arg "CLANG_RT_WASM32_SHA256=$clang_rt_sha" \
    --tag "$build_image" \
    --file third_party/sqlite/Dockerfile \
    third_party/sqlite
build_image_id=$(docker image inspect --format '{{.Id}}' "$build_image")
compiler_version=$(docker run --rm "$build_image" clang-17 --version | sed -n '1p')
expected_compiler_version=$(read_lock wasi_build.compiler_version)
if [[ $compiler_version != "$expected_compiler_version" ]]; then
    printf 'clang version mismatch: %s != %s\n' "$compiler_version" "$expected_compiler_version" >&2
    exit 1
fi

bridge_rust_toolchain=$(
    python3 - <<'PY'
import json

with open("third_party/wanco/source-lock.json", encoding="utf-8") as source:
    print(json.load(source)["build"]["rust_toolchain"])
PY
)
bridge_source_sha=$(
    {
        sha256sum \
            third_party/sqlite/bridge-Cargo.lock \
            third_party/sqlite/bridge-workspace.toml
        find \
            crates/runtime/visa_wanco_wasi \
            crates/runtime/visa_wasi_protocol \
            -type f -print0 |
            sort -z |
            xargs -0 sha256sum
    } | sha256sum | cut -d' ' -f1
)
wanco_image_short=${wanco_image_id#sha256:}
bridge_cache="$cache_root/bridge-${bridge_source_sha:0:12}-${wanco_image_short:0:12}"
bridge="$bridge_cache/libvisa_wanco_wasi.a"
if [[ ! -f $bridge ]]; then
    bridge_publication="$bridge_cache.incomplete.$$"
    if [[ -e $bridge_publication ]]; then
        printf 'refusing existing incomplete bridge path: %s\n' "$bridge_publication" >&2
        exit 1
    fi
    mkdir "$bridge_publication"
    docker run --rm \
        --network bridge \
        --security-opt label=disable \
        --volume "$repo_root:/repo:ro" \
        --volume "$bridge_publication:/bridge-out" \
        --workdir / \
        --env CARGO_TARGET_DIR=/cargo-target \
        --env "RUSTUP_TOOLCHAIN=$bridge_rust_toolchain" \
        --env "VISA_HOST_UID=$(id -u)" \
        --env "VISA_HOST_GID=$(id -g)" \
        --tmpfs /bridge-work:exec,size=67108864 \
        --tmpfs /cargo-target:exec,size=2147483648 \
        "$build_image" sh -ec '
            install -d /bridge-work/crates/runtime
            install -m 0644 \
                /repo/third_party/sqlite/bridge-workspace.toml \
                /bridge-work/Cargo.toml
            install -m 0644 \
                /repo/third_party/sqlite/bridge-Cargo.lock \
                /bridge-work/Cargo.lock
            cp -a \
                /repo/crates/runtime/visa_wasi_protocol \
                /repo/crates/runtime/visa_wanco_wasi \
                /bridge-work/crates/runtime/
            cd /bridge-work
            cargo build --release --locked -p visa_wanco_wasi
            install -m 0644 \
                /cargo-target/release/libvisa_wanco_wasi.a \
                /bridge-out/libvisa_wanco_wasi.a
            chown "$VISA_HOST_UID:$VISA_HOST_GID" \
                /bridge-out/libvisa_wanco_wasi.a
        ' || {
            find "$bridge_publication" -xdev -depth -delete
            exit 1
        }
    mv "$bridge_publication" "$bridge_cache"
fi

while read -r symbol; do
    if ! nm -g --defined-only "$bridge" |
        awk -v expected="$symbol" '$3 == expected { found = 1 } END { exit found ? 0 : 1 }'
    then
        printf 'Wanco bridge lacks stock-SQLite import symbol: %s\n' "$symbol" >&2
        exit 1
    fi
done < <(
    python3 - <<'PY'
import importlib.util
from pathlib import Path

path = Path("scripts/check-sqlite-source.py")
spec = importlib.util.spec_from_file_location("sqlite_source", path)
if spec is None or spec.loader is None:
    raise SystemExit("cannot load stock-SQLite source checker")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
for namespace, name in module.EXPECTED_IMPORTS:
    if namespace == "wasi_snapshot_preview1":
        print(f"wasi_snapshot_preview1_{name}")
    else:
        print(name)
PY
)
bridge_sha=$(sha256sum "$bridge" | cut -d' ' -f1)
bridge_rustc_version=$(
    docker run --rm --env "RUSTUP_TOOLCHAIN=$bridge_rust_toolchain" "$build_image" rustc --version
)
bridge_cargo_version=$(
    docker run --rm --env "RUSTUP_TOOLCHAIN=$bridge_rust_toolchain" "$build_image" cargo --version
)

artifact_root=${VISA_STOCK_SQLITE_OUT:-"$repo_root/target/.ci-artifacts/stock-sqlite-build"}
if [[ $artifact_root != /* ]]; then
    artifact_root="$repo_root/$artifact_root"
fi
artifact_root=$(realpath -m "$artifact_root")
if [[ $artifact_root == / || $artifact_root == "$repo_root" ]]; then
    printf 'refusing broad stock-SQLite artifact path: %s\n' "$artifact_root" >&2
    exit 1
fi
if [[ -e $artifact_root ]]; then
    printf 'refusing existing stock-SQLite artifact path: %s\n' "$artifact_root" >&2
    printf '%s\n' 'set VISA_STOCK_SQLITE_OUT to a fresh path for a new build' >&2
    exit 1
fi

work_root=$(mktemp -d "$cache_root/.build-work.XXXXXXXX")
publication="$artifact_root.incomplete.$$"
provider_pid=
cleanup_work() {
    if [[ -n $provider_pid ]]; then
        kill "$provider_pid" >/dev/null 2>&1 || true
        wait "$provider_pid" >/dev/null 2>&1 || true
    fi
    if [[ -e $work_root ]]; then
        case $(realpath "$work_root") in
            "$cache_root"/.build-work.*) find "$work_root" -xdev -depth -delete ;;
            *) printf 'refusing unexpected stock-SQLite work cleanup: %s\n' "$work_root" >&2 ;;
        esac
    fi
    if [[ -e $publication ]]; then
        if [[ $(realpath "$publication") == "$artifact_root.incomplete.$$" ]]; then
            find "$publication" -xdev -depth -delete
        fi
    fi
}
trap cleanup_work EXIT

mkdir "$work_root/source"
python3 - "$archive" "$work_root/source" <<'PY'
import sys
import zipfile
from pathlib import Path

archive = Path(sys.argv[1])
root = Path(sys.argv[2])
with zipfile.ZipFile(archive) as source:
    source.extractall(root)
PY
source_root="$work_root/source/sqlite-amalgamation-3530400"
python3 scripts/check-sqlite-source.py --source "$source_root"

host_uid=$(id -u)
host_gid=$(id -g)
docker run --rm \
    --user "$host_uid:$host_gid" \
    --volume "$work_root:/work:Z" \
    --volume "$repo_root/third_party/sqlite:/visa-sqlite:ro,Z" \
    --workdir /work \
    --env LC_ALL=C \
    --env TZ=UTC \
    "$build_image" sh -ec '
        set -eu
        clang-17 --target=wasm32-wasi --sysroot=/usr \
            -O1 -Wall -Wextra -Werror \
            -I/visa-sqlite/abi \
            -c /visa-sqlite/abi/visa_sqlite_wasi_compat.c \
            -o /work/visa_sqlite_wasi_compat.o
        clang-17 --target=wasm32-wasi --sysroot=/usr \
            -O1 \
            -D_WASI_EMULATED_SIGNAL \
            -D_WASI_EMULATED_PROCESS_CLOCKS \
            -D_WASI_EMULATED_GETPID \
            -DSQLITE_THREADSAFE=0 \
            -DSQLITE_DEFAULT_MEMSTATUS=0 \
            -DSQLITE_OMIT_LOAD_EXTENSION \
            -DSQLITE_OMIT_WAL \
            -DSQLITE_NOHAVE_SYSTEM \
            -include /visa-sqlite/abi/visa_sqlite_wasi_compat.h \
            source/sqlite-amalgamation-3530400/shell.c \
            source/sqlite-amalgamation-3530400/sqlite3.c \
            /work/visa_sqlite_wasi_compat.o \
            -lwasi-emulated-signal \
            -lwasi-emulated-process-clocks \
            -lwasi-emulated-getpid \
            -o /work/sqlite3-v3.53.4.wasm
    '
python3 scripts/check-sqlite-source.py --wasm "$work_root/sqlite3-v3.53.4.wasm"
python3 - "$work_root/sqlite3-v3.53.4.wasm" "$work_root/imports.json" <<'PY'
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

wasm = Path(sys.argv[1])
output = Path(sys.argv[2])
checker_path = Path("scripts/check-sqlite-source.py")
spec = importlib.util.spec_from_file_location("sqlite_source", checker_path)
if spec is None or spec.loader is None:
    raise SystemExit("cannot load stock-SQLite source checker")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
document = {
    "schema": "visa-stock-sqlite-wasm-imports-v1",
    "wasm_sha256": hashlib.sha256(wasm.read_bytes()).hexdigest(),
    "imports": [
        {"module": module, "name": name}
        for module, name in checker.wasm_function_imports(wasm)
    ],
}
output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

docker run --rm \
    --user "$host_uid:$host_gid" \
    --volume "$work_root:/work:Z" \
    --volume "$bridge:/bridge/libvisa_wanco_wasi.a:ro,z" \
    --workdir /work \
    --env "VISA_WANCO_OPTIMIZATION=$carrier_optimization" \
    "$build_image" sh -ec '
        set -eu
        wanco --enable-cr "$VISA_WANCO_OPTIMIZATION" -c \
            -o /work/sqlite3-v3.53.4-wanco-o1.ll \
            /work/sqlite3-v3.53.4.wasm
        clang++-17 -std=c++20 -flto -no-pie "$VISA_WANCO_OPTIMIZATION" -g0 \
            -Wl,--build-id=none \
            /work/sqlite3-v3.53.4-wanco-o1.ll \
            -I/wanco/lib-rt \
            /usr/local/lib/libwanco_rt.a \
            /bridge/libvisa_wanco_wasi.a \
            -lprotobuf -lunwind -lunwind-x86_64 -lelf \
            -ldl -lpthread -lm \
            -o /work/sqlite3-v3.53.4-wanco-o1
    '

cargo build --locked -p visa_wasi_host
host_binary="$repo_root/target/debug/visa_wasi_host"
smoke_root="$work_root/smoke"
mkdir -m 0700 "$smoke_root"
session=11111111111111111111111111111111
owner=22222222222222222222222222222222
client=33333333333333333333333333333333
admin_capability=$(printf '44%.0s' {1..32})
guest_capability=$(printf '55%.0s' {1..32})
provider_database="$smoke_root/provider.sqlite"
provider_socket="$smoke_root/provider.sock"
"$host_binary" create \
    "$provider_database" \
    "$session" \
    "$admin_capability" \
    "$guest_capability" \
    1 \
    "workload/basic.sql=$repo_root/third_party/sqlite/workload/basic.sql"
"$host_binary" serve "$provider_database" "$provider_socket" \
    >"$smoke_root/provider.stdout" 2>"$smoke_root/provider.stderr" &
provider_pid=$!
for _ in {1..100}; do
    if [[ -S $provider_socket ]]; then
        break
    fi
    if ! kill -0 "$provider_pid" >/dev/null 2>&1; then
        printf '%s\n' 'stock-SQLite smoke provider exited during startup' >&2
        exit 1
    fi
    sleep 0.05
done
if [[ ! -S $provider_socket ]]; then
    printf '%s\n' 'stock-SQLite smoke provider socket was not published' >&2
    exit 1
fi

docker run --rm \
    --network none \
    --security-opt label=disable \
    --user "$host_uid:$host_gid" \
    --volume "$smoke_root:/case:Z" \
    --volume "$work_root:/aot:ro,Z" \
    --workdir /case \
    --env VISA_WASI_SOCKET=/case/provider.sock \
    --env "VISA_WASI_SESSION_ID=$session" \
    --env "VISA_WASI_OWNER_ID=$owner" \
    --env "VISA_WASI_CLIENT_ID=$client" \
    --env "VISA_WASI_GUEST_CAPABILITY=$guest_capability" \
    --env VISA_WASI_AUTHORITY_EPOCH=1 \
    "$build_image" \
    /aot/sqlite3-v3.53.4-wanco-o1 \
    -- -batch -bail workload/accounts.db '.read workload/basic.sql' \
    >"$smoke_root/guest.stdout" 2>"$smoke_root/guest.stderr"

"$host_binary" control "$provider_socket" "$admin_capability" status \
    >"$smoke_root/provider-status.json"
"$host_binary" control "$provider_socket" "$admin_capability" \
    materialize workload/accounts.db "$smoke_root/materialized.db" \
    >"$smoke_root/materialize.json"
"$host_binary" control "$provider_socket" "$admin_capability" shutdown \
    >"$smoke_root/shutdown.json"
wait "$provider_pid"
provider_pid=

python3 - "$smoke_root" <<'PY'
import json
import sqlite3
import sys
from pathlib import Path

root = Path(sys.argv[1])
expected = [
    "delete",
    "journal_mode=delete",
    "synchronous=2",
    "account=1:875",
    "account=2:1125",
    "transaction=tx-0001:1:2:125",
    "integrity=ok",
    "foreign_keys=0",
]
actual = root.joinpath("guest.stdout").read_text(encoding="utf-8").splitlines()
if actual != expected:
    raise SystemExit(f"stock-SQLite guest output differs: {actual!r}")
status_document = json.loads(root.joinpath("provider-status.json").read_text(encoding="utf-8"))
status = status_document.get("status")
if not status_document.get("ok") or not isinstance(status, dict):
    raise SystemExit("stock-SQLite provider status is not successful")
if status.get("mode") != "active" or status.get("authority_epoch") != 1:
    raise SystemExit("stock-SQLite provider authority changed during smoke run")
if status.get("bytes_read", 0) <= 0 or status.get("bytes_written", 0) <= 0:
    raise SystemExit("stock-SQLite workload did not read and write provider bytes")
if status.get("effects", 0) <= 0 or status.get("completed_requests") != status.get("effects"):
    raise SystemExit("stock-SQLite workload left an incomplete provider request")
if (
    status.get("paths") != 4
    or status.get("objects") != 4
    or status.get("open_descriptors") != 1
    or status.get("locks") != 0
):
    raise SystemExit("stock-SQLite workload left a journal, dotfile lock, or descriptor behind")
database = root / "materialized.db"
connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
try:
    integrity = connection.execute("PRAGMA integrity_check").fetchall()
    foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
    accounts = connection.execute(
        "SELECT account_id, balance FROM accounts ORDER BY account_id"
    ).fetchall()
    transactions = connection.execute(
        "SELECT txid, from_account, to_account, amount "
        "FROM transactions ORDER BY txid"
    ).fetchall()
    account_columns = connection.execute("PRAGMA table_info(accounts)").fetchall()
    transaction_columns = connection.execute("PRAGMA table_info(transactions)").fetchall()
    transaction_foreign_keys = connection.execute(
        "PRAGMA foreign_key_list(transactions)"
    ).fetchall()
finally:
    connection.close()
if integrity != [("ok",)] or foreign_keys:
    raise SystemExit("native SQLite rejected the materialized database")
if accounts != [(1, 875), (2, 1125)] or sum(value for _, value in accounts) != 2000:
    raise SystemExit(f"materialized account invariant differs: {accounts!r}")
if transactions != [("tx-0001", 1, 2, 125)]:
    raise SystemExit(f"materialized transaction identity differs: {transactions!r}")
account_shape = [(row[1], row[2].upper(), row[3], row[5]) for row in account_columns]
transaction_shape = [(row[1], row[2].upper(), row[3], row[5]) for row in transaction_columns]
if account_shape != [("account_id", "INTEGER", 0, 1), ("balance", "INTEGER", 1, 0)]:
    raise SystemExit(f"materialized accounts schema differs: {account_shape!r}")
if transaction_shape != [
    ("txid", "TEXT", 1, 1),
    ("from_account", "INTEGER", 1, 0),
    ("to_account", "INTEGER", 1, 0),
    ("amount", "INTEGER", 1, 0),
]:
    raise SystemExit(f"materialized transactions schema differs: {transaction_shape!r}")
foreign_key_shape = {(row[3], row[2], row[4]) for row in transaction_foreign_keys}
if foreign_key_shape != {
    ("from_account", "accounts", "account_id"),
    ("to_account", "accounts", "account_id"),
}:
    raise SystemExit(f"materialized transaction foreign keys differ: {foreign_key_shape!r}")
if root.joinpath("accounts.db-journal").exists() or root.joinpath("accounts.db.lock").exists():
    raise SystemExit("stock-SQLite smoke left a journal or dotfile lock behind")
PY

mkdir -p "$(dirname "$artifact_root")"
mkdir "$publication"
install -m 0644 "$work_root/sqlite3-v3.53.4.wasm" "$publication/sqlite3-v3.53.4.wasm"
install -m 0755 \
    "$work_root/sqlite3-v3.53.4-wanco-o1" \
    "$publication/sqlite3-v3.53.4-wanco-o1"
install -m 0644 "$work_root/imports.json" "$publication/imports.json"
install -m 0644 "$smoke_root/guest.stdout" "$publication/smoke.stdout"
install -m 0644 "$smoke_root/guest.stderr" "$publication/smoke.stderr"
install -m 0644 "$smoke_root/provider-status.json" "$publication/smoke-provider-status.json"

build_recipe_sha=$(sha256sum scripts/build-stock-sqlite.sh | cut -d' ' -f1)
host_binary_sha=$(sha256sum "$host_binary" | cut -d' ' -f1)
carrier_ir_sha=$(sha256sum "$work_root/sqlite3-v3.53.4-wanco-o1.ll" | cut -d' ' -f1)
carrier_ir_size=$(stat -c %s "$work_root/sqlite3-v3.53.4-wanco-o1.ll")
python3 - "$publication" "$lock_sha" "$version" \
    "$wanco_revision" "$wanco_image" "$wanco_image_id" \
    "$wanco_compiler_sha" "$wanco_runtime_sha" "$wanco_source_lock_sha" \
    "$wanco_receipt_sha" "$build_image" "$build_image_id" "$compiler_version" \
    "$compiler_optimization" "$carrier_optimization" "$bridge_sha" \
    "$bridge_rustc_version" "$bridge_cargo_version" "$build_recipe_sha" \
    "$host_binary_sha" "$carrier_ir_sha" "$carrier_ir_size" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

(
    root,
    source_lock_sha,
    sqlite_version,
    wanco_revision,
    wanco_image,
    wanco_image_id,
    wanco_compiler_sha,
    wanco_runtime_sha,
    wanco_source_lock_sha,
    wanco_receipt_sha,
    build_image,
    build_image_id,
    compiler_version,
    compiler_optimization,
    carrier_optimization,
    bridge_sha,
    rustc_version,
    cargo_version,
    build_recipe_sha,
    host_binary_sha,
    carrier_ir_sha,
    carrier_ir_size,
) = sys.argv[1:]
root = Path(root)
artifacts = {}
for path in sorted(root.iterdir()):
    payload = path.read_bytes()
    artifacts[path.name] = {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}
status = json.loads(root.joinpath("smoke-provider-status.json").read_text(encoding="utf-8"))["status"]
receipt = {
    "schema": "visa-stock-sqlite-build-receipt-v1",
    "source_lock_sha256": source_lock_sha,
    "sqlite_version": sqlite_version,
    "zero_upstream_source_patches": True,
    "workload_transport": "provider-backed-.read",
    "database_guest_path": "workload/accounts.db",
    "script_guest_path": "workload/basic.sql",
    "journal_mode": "delete",
    "synchronous": "full",
    "native_sqlite_oracle": {
        "integrity_check": "ok",
        "foreign_key_check_rows": 0,
        "accounts": [[1, 875], [2, 1125]],
        "transaction_txids": ["tx-0001"],
        "balance_sum": 2000,
    },
    "provider_status": status,
    "wanco_revision": wanco_revision,
    "wanco_optimization": carrier_optimization,
    "wanco_image": wanco_image,
    "wanco_image_id": wanco_image_id,
    "wanco_compiler_sha256": wanco_compiler_sha,
    "wanco_runtime_sha256": wanco_runtime_sha,
    "wanco_source_lock_sha256": wanco_source_lock_sha,
    "wanco_build_receipt_sha256": wanco_receipt_sha,
    "build_image": build_image,
    "build_image_id": build_image_id,
    "compiler": compiler_version,
    "compiler_optimization": compiler_optimization,
    "bridge_sha256": bridge_sha,
    "bridge_rustc": rustc_version,
    "bridge_cargo": cargo_version,
    "build_recipe_sha256": build_recipe_sha,
    "smoke_host_binary_sha256": host_binary_sha,
    "expected_imports": 28,
    "wanco_ir": {
        "sha256": carrier_ir_sha,
        "size": int(carrier_ir_size),
        "retained": False,
    },
    "artifacts": artifacts,
    "non_claims": [
        "power-loss durability",
        "torn-sector safety",
        "device-cache ordering",
        "fine-grained concurrent SQLite locking",
    ],
}
path = root / "receipt.json"
temporary = root / "receipt.json.tmp"
temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
os.replace(temporary, path)
PY

mv "$publication" "$artifact_root"
trap - EXIT
cleanup_work
printf 'Stock SQLite Wasm: %s\n' "$artifact_root/sqlite3-v3.53.4.wasm"
printf 'Stock SQLite Wanco executable: %s\n' "$artifact_root/sqlite3-v3.53.4-wanco-o1"
printf 'Stock SQLite build receipt: %s\n' "$artifact_root/receipt.json"
