# Target Runtime Default Profile

This file pins the reference target-runtime defaults.

```text
real target        = riscv64-qemu-virt-singlehart
payload            = FakeAotBlobV1 inside TargetArtifactImage
patching           = data only; executable patches rejected
hash               = canonical zero-field image hash + section hashes
signature          = unsigned-research by default; dev-ed25519 optional
osctl              = target-to-host JSONL ViewV1
panic_ring_size = 65536
panic record max   = 4096
icache             = single-hart local
SMP publish        = rejected unless STW profile exists
```

Pinned RV64I bytes:

```text
entry_return_ok:
    13 05 00 00
    67 80 00 00

entry_hostcall_tail:
    67 80 05 00

entry_trap_ebreak:
    73 00 10 00
```

Hostcall convention:

```text
a0 = HostcallFrameV1*
a1 = trampoline pointer, FakeAotBlob only
```

Unsigned research means:

```text
hash verified
signature not enforced
not signature verified
```

Store reboot defaults:

```text
3 restarts per 10s window
backoff 10ms, 100ms, 1000ms
reuse StoreId and bump generation for same logical fault domain
revoke old caps
cancel old waits
grant new caps through policy
```

QEMU default:

```text
OpenSBI S-mode
-M virt -m 512M -smp 1 -bios default -kernel target-runtime.elf -nographic
FDT from a1
UART = stdout-path / serial0 / ns16550-like
UART mode = polled TX only
```
