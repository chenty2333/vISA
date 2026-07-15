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
  `a890e5c3e25138662c213f19280ba3b209939813` and binary SHA-256
  `574580e5190f9aab2e54d37f3959c6872a1226ede5b22c064fa3609f35a3c689`,
  including same-Registry service rebind. Do not relabel it as Registry
  replacement or a production retained path.
- [x] T015 Qualify the Nexus-local model/oracle/fault-matrix and production
  Registry refinement from clean exact SHA
  `a890e5c3e25138662c213f19280ba3b209939813`; bind receipt SHA-256
  `4245c69f74bd492eb2aba0114c0d9584f112664c6d09854a157c4413c5760091`
  and v2 lock SHA-256
  `306ee1fff5a53b010f9906084925ca5fa6af44bd779bf3658957f4552a0bcb21`.
- [x] T016 Execute the real logical-request experiment with post-durable
  ownership Commit acknowledgement loss and terminal Nexus response loss before
  adapter acceptance; prove exact recovery without duplicate execution or
  publication.
- [x] T017 Implement and smoke the standalone exact-two-file process publisher,
  independent verifier, relocation, and relocated recheck.
- [ ] T018 Rerun that publisher after this work is committed and bind the final
  clean vISA SHA into the artifact.
- [ ] T019 Run full local and Docker gates, push the closing revision, and require
  exact-SHA CI success.
- [ ] T020 Record the final combined exact-revision/post-download receipt.
- [ ] T021 Extract accepted decisions into canonical documentation and remove
  this temporary specification.
