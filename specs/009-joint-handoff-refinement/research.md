# Feature 009 Research Boundary

## Candidate Contribution

Prepared records, two-phase commit, fencing tokens, and migration transactions
are established mechanisms. The candidate contribution is the executable
refinement between three distinct authorities:

1. vISA portable component and resource semantics;
2. a durable, non-equivocating ownership decision; and
3. kernel-enforced closure of the source effect cohort.

The experiment asks whether a reversible semantic freeze and an irreversible
native close can be composed without copying device state or allowing either
project to own the other's ledger.

## Related-Work Obligations

The final research artifact must compare the protocol with two-phase commit,
atomic RPC, presumed-abort/presumed-commit recovery, fencing leases, live/VM
migration transactions, external-effect journaling, confidential migration,
attestation-bound key release, and rollback/freshness mechanisms.

Novelty must not be claimed for the existence of a prepared state or a signed
receipt. Evaluation must isolate what the vISA/Nexus refinement adds over these
mechanisms.

## Rollback Counterexample

The formal artifact must retain a negative configuration in which the ownership
log can roll back and the same issuer can authenticate both abort and commit for
one reservation. It must find the expected dual-authority counterexample. This
negative result fixes the non-equivocating, rollback-resistant decision log as
an explicit assumption until a separate freshness anchor is qualified.

## Availability Boundary

Fail-closed safety permits indefinite freezing while the ownership authority is
unavailable. Progress is claimed only under explicit fairness assumptions that
the ownership query, local closure worker, and destination recovery eventually
become available. Permanent source loss and delegated cleanup authority are not
part of the first accepted cell.
