# Contract: Phase 2 Contract Core Evidence

## Purpose

This contract defines the expected evidence package for Feature 002. It is a
feature-local contract evidence envelope that reuses existing artifact or
migration package-shaped structures to store Phase 2 semantic-model evidence.
It does not define a post-completion compatibility policy and does not claim
artifact execution, profile-gate completion, real substrate behavior, frontend
compatibility breadth, migration restoration, or cross-ISA portability.

## Required Evidence Envelope

An accepted Feature 002 evidence envelope must contain:

- Feature identity: `002-contract-core-stabilization`.
- Evidence boundary: `semantic-model`.
- Carrier kind: artifact-shaped or migration-shaped.
- Contract facts:
  - object references;
  - contract edges;
  - command transaction results;
  - event evidence;
  - stable views;
  - validation violations;
  - evidence-boundary metadata.
- Phase 2 coverage matrix:
  - coverage unit id;
  - semantic family;
  - owned surface;
  - positive scenario reference;
  - negative scenario reference;
  - coverage status.
- Overclaim guards:
  - artifact/profile claims are excluded;
  - frontend/personality claims are excluded;
  - substrate hardware claims are excluded;
  - migration and portability claims are excluded;
  - raw host state and private runtime state are excluded.

## Required Coverage Units

The evidence envelope must prove positive and negative coverage for every
Phase 2-owned unit across:

- object identity;
- generation;
- graph edges;
- capability authority;
- wait state;
- event evidence;
- trap attribution;
- cleanup;
- guest memory;
- stable views;
- graph validation.

The envelope must not add later-phase object kinds, command areas, or state
transitions merely because they exist in current code. A later-phase surface may
appear only as a generic evidence shape required to validate a Phase 2-owned
unit.

## Validation Contract

Validation must reject an evidence envelope when:

- any Phase 2-owned coverage unit lacks a positive scenario;
- any Phase 2-owned coverage unit lacks a negative scenario;
- a live edge targets a tombstone, dead owner, stale generation, or missing
  object;
- a historical edge lacks an exact generation;
- a cleanup-effect edge creates live ownership or authority;
- a rejected command mutates semantic state;
- event or view evidence relies only on prose logs, debugger output, benchmark
  output, or CLI formatting;
- raw page tables, raw register frames, native pointers, substrate bindings,
  frontend ABI handles, or private runtime state are treated as semantic truth;
- carrier reuse is reported as artifact/profile, frontend/personality,
  substrate, migration, or portability evidence;
- validation stops after the first violation and hides independently
  detectable failures.

Validation may accept an envelope only when all Phase 2-owned coverage units
are covered and every claim names `semantic-model` as the weakest exercised
evidence boundary.

## Feature-Local Shape Rule

The evidence shape may change while Feature 002 is in progress. Earlier
in-feature evidence drafts are not compatibility commitments. This feature does
not define additive compatibility, migration rules, or a frozen schema for
future features.

## Later-Phase Deferral Contract

The following surfaces are out of scope for Feature 002 except as generic
contract evidence shapes:

- Phase 3 artifact/profile gate behavior, including load compatibility,
  complete HostcallFrame behavior, target TrapMap execution claims, and package
  root execution evidence.
- Phase 4 frontend/personality behavior, including Linux, WASI, service,
  filesystem, socket, futex, epoll, signal, and service breadth.
- Phase 5 substrate authority behavior, including DMW, DMA, MMIO, IRQ, event
  queue, code publish, unsupported/degraded hardware authority, and extraction
  claims.
- Phase 6 snapshot and cross-ISA portability behavior, including migration
  restoration, semantic state survival across substrate changes, and
  host-binding exclusion claims.

## Review Checklist

- The envelope names Feature 002.
- The envelope names `semantic-model` as the evidence boundary.
- The envelope uses artifact-shaped or migration-shaped records only as a
  carrier.
- The coverage matrix lists all Phase 2-owned units.
- Every listed unit has both positive and negative scenarios.
- All independently detectable violations are reported.
- No stronger roadmap-phase claim is made.
