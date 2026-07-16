# Feature 009 Tasks

- [x] T001 Record the threat model, kill conditions, hypothesis, protocol shape,
  bounded scope, and exit claim.
- [x] T002 Freeze versioned joint receipt and mapping schemas.
- [x] T003 Implement the production joint reducer and durable state codec.
- [x] T004 Implement typed native receipt validation and terminal-decision
  idempotency.
- [x] T005 Implement the vISA coordinator projection adapter, including durable
  attempt/observed/completion records for source abort, source fence, and
  destination activation.
- [x] T006 Implement the reference ownership decision log.
- [x] T007 Implement the reference effect-freeze/closure peer.
- [x] T008 Implement the independent Rust oracle and mutation corpus.
- [x] T009 Implement and model-check the bounded TLA+ specification.
- [x] T010 Implement the 16-case normative system matrix, supplemental reference
  retained-tombstone case, and raw trace capture.
- [x] T011 Implement the evidence schema, publisher, exact-artifact inventory,
  relocation check, and independent semantic verifier.
- [x] T012 Add active-spine, file-size, dependency-direction, Docker, CI-contract,
  artifact-retention, and exact-SHA closure gates.
- [x] T013 Execute the 16-case reference peer cell plus the supplemental retained
  case and the independently verified HostSubstrate vertical.
- [x] T014 Run all four live process tests against Nexus exact SHA
  `8e5123c46569e8ebdaba9f4f56bea6584ab58586` and binary SHA-256
  `6bf845f8fecd2b3ff5833aa505f2a392fa3e07d726326cf65d07b39a87358f51`,
  including same-Registry service rebind. Do not relabel it as Registry
  replacement or a production retained path.
- [x] T015 Qualify the Nexus-local model/oracle/fault-matrix and production
  Registry refinement from clean exact SHA
  `8e5123c46569e8ebdaba9f4f56bea6584ab58586`; bind receipt SHA-256
  `f155d9d796ee4928b68ca2317268f5d622c4b3f2878440895e2c811add24ae6a`
  and v2 lock SHA-256
  `21b5404bc5c1ad1f48c4ffe37cf455d104acac8ab9deca98f326d7c9b06072d9`.
- [x] T016 Execute the real logical-request experiment with post-durable
  ownership Commit acknowledgement loss and terminal Nexus response loss before
  adapter acceptance; prove exact recovery without duplicate execution or
  publication.
- [x] T017 Implement and smoke the standalone strict three-file process
  publisher, independent verifier, relocation, and relocated recheck; keep the
  logical supplemental as a distinct strict five-file artifact.
- [ ] T018 Rerun that publisher after this work is committed and bind the final
  clean vISA SHA into the artifact.
- [ ] T019 Run full local and Docker gates, push the closing revision, and require
  exact-SHA CI success.
- [ ] T020 Record the final combined exact-revision/post-download receipt.
- [ ] T021 Extract accepted decisions into canonical documentation and remove
  this temporary specification.
