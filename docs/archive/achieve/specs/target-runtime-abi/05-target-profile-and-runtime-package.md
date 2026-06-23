# Target Profile And Runtime Package

The target must declare enforceable capabilities before artifacts load.

## Profile Rule

```text
reported profile = what target claims exists
enforced profile = what loader/substrate can prove
artifact may run only when required profile <= enforced profile
```

Missing required support rejects the artifact. Optional support may degrade, but
degradation must be event-visible and osctl-visible.

## Default Research Target

```text
target = riscv64-qemu-virt-singlehart
boot = OpenSBI S-mode
entry a0 = hart id
entry a1 = FDT pointer
payload = FakeAotBlobV1 in TargetArtifactImage
osctl = target-to-host JSONL ViewV1
panic ring = 64 KiB, 4 KiB max record
icache = single-hart local
```

Mandatory FDT discovery:

```text
memory ranges
timebase-frequency
stdout-path
stdout UART node
```

Stdout UART resolution:

```text
/chosen/stdout-path
/aliases/serial0
first ns16550-like UART
```

Accepted UART compatible strings include `ns16550a`, `ns16550`, or any string
containing `ns16550`. UART support is polled TX only.

Default memory profile:

```text
0x8020_0000    runtime
0x8100_0000    artifact staging
0x8200_0000    semantic heap
0x8400_0000    guest memory
0x8800_0000    DMW reserve
0x9000_0000    panic ring
```

This layout is a profile, not a universal ABI.

## Runtime Package

Keep identities distinct:

```text
package -> artifact -> CodeObject -> Store -> Activation
```

Package verification checks schema, target profile, artifact envelopes,
capability manifests, hash/signature policy, boot root, duplicate identities,
and profile compatibility. Verification creates a load plan only; it must not
publish code or enter a Store.

The load-plan evidence is the single normalized source for package roots,
artifact manifest facts, capability manifest facts, target profile facts, hash
status, and signature status. Accepted research artifacts use:

```text
hash_status       = manifest-bound
signature_status  = profile-bound-unverified
signature_verified = false
```

The same facts must be exported through semantic artifact records, semantic
package target-artifact evidence, and osctl JSON. Rejected artifacts must expose
machine-readable rejection evidence instead of disappearing behind CLI prose.

## Store Reboot

```text
Store/Wasm fault may reboot Store
contract/substrate panic does not reboot Store automatically
same fault domain may reuse StoreId and bump generation
old generation is tombstoned
old cleanup cannot mutate new generation
old caps and waits do not cross reboot
```
