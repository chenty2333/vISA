# Capability Discovery And Profiles

The substrate reports what it can enforce before artifacts load.

## Discovery Owns

```text
SubstrateCapabilitySet
target architecture and pointer width
authority availability
DMW / DMA / MMIO / IRQ modes
code publish and icache protocol
timer and event queue support
snapshot/replay support
osctl extraction support
```

## Rules

```text
required artifact feature missing -> load rejected
optional feature missing -> degraded mode, event-visible
forbidden feature present and requested -> policy rejection
runtime unexpected use -> Unsupported event
reported support must match enforceable support
```

Profiles are virtual ISA feature sets, not marketing labels.

## Review Smell

```text
capability discovered by crashing at first use
optional degradation not event-visible
profile claims DMA/MMIO/IRQ without enforcement path
artifact starts before profile compatibility is checked
```
