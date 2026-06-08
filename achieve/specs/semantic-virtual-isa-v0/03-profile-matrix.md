# Profile Matrix

Profiles are Semantic Virtual ISA feature sets. They are load and conformance
contracts, not marketing labels.

Artifacts declare required, optional, and forbidden profile features. Targets
report enforceable capability before load. The loader rejects an artifact when
required features are missing or forbidden features are requested.

## Stable Levels

```text
Profile 0: reference harness
    Semantic model only. Contract effects can be generated and validated without
    proving real substrate authority.

Profile 1: base machine authority
    Console, timer, event queue, basic hostcall/trap attribution, and visible
    unsupported events.

Profile 2: memory authority
    GuestAddressSpace, VmaRegion, PageObject, logical DMW, generation-safe
    user-buffer and memory-boundary checks.

Profile 3: device authority
    MMIO, IRQ, DMA, queues, descriptors, device capability gates, and generation
    visibility for mediated device operations.

Profile 4: snapshot and replay
    Snapshot barriers, deterministic replay support, migration-package roots,
    no active non-migratable leases, and stable osctl extraction.
```

Profile levels are monotonic for load compatibility, but individual feature
values still matter. For example, `DmaSupport::BounceBuffer` and
`DmaSupport::IommuStrict` are both device-capable modes, but they are not
identical enforcement claims.

## Compatibility Rule

```text
reported profile = what target claims exists
enforced profile = what loader/substrate can prove
artifact may run only when required profile <= enforced profile
optional feature missing -> event-visible degraded mode
forbidden feature present and requested -> policy rejection
unexpected runtime use -> Unsupported event
```

The stable code representation lives in the `visa_profile` crate. Specs should
refer to that compatibility matrix instead of inventing local string matching.

## Matrix Dimensions

```text
architecture and pointer width
console / timer / event support
guest memory and DMW mode
code publish and icache protocol
DMA mode
MMIO mode
IRQ mode
snapshot / replay mode
osctl extraction mode
interface requirements
evidence boundary level
```

## Enforcement Requirements

Every profile claim must name the enforcement path:

```text
manifest requirement
SubstrateCapabilitySet report
loader compatibility decision
capability and generation gate
EventLog and stable view evidence
substrate trait behavior or explicit Unsupported event
```

## Review Smells

```text
profile claims DMA/MMIO/IRQ without enforcement path
artifact starts before compatibility is checked
optional degradation is not event-visible
profile parsing differs across crates
frontend interface requirement is confused with substrate authority
```
