# Object Identity And References

Every durable semantic object is identified by:

```text
kind
id
generation
```

`id` names logical identity. `generation` names an incarnation. Reuse `id` only
when policy says the logical object survived across incarnations, such as Store
reboot. Otherwise allocate a new id.

## Required Properties

```text
ObjectRef is never null.
Generation is part of authority.
Generation is part of cleanup targeting.
Dead or retired objects leave tombstones.
Historical records may point to tombstoned generations.
Live references must not point to dead/tombstoned generations.
```

## External Objects

External objects are still represented as ObjectRefs. Provider/class metadata
may refine them, but it must not replace generation-bearing identity.

## Review Smell

```text
string label used as authority
record contains id without generation
cleanup step targets only StoreId
hostcall frame trusts caller-provided identity
osctl output exposes ids that cannot be converted to ObjectRef
```
