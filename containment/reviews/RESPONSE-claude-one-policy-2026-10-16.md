# Response to the one-policy review (2026-10-16 night)

Review: `containment/reviews/REVIEW-claude-one-policy-2026-10-16.md`, of 37e3cca. No rule in
`game.sb` changed; the edits there are comments only, so the normalized policy is unchanged.

| finding | what changed |
|---|---|
| M1 | `containment/go/profiles/game.sb:2-3`: this file is the one policy; d1-nonet embeds it, the three `build.rs` and `fntest.rs` generate `D1_NETGATE_PROFILE` from it. `:32-33`: every global-name here must be in `netgate_delegates`, and the gate refuses when the counts differ. |
| M2 | `containment/agent-containment.md:63-66`: inside the agent sandbox the apply is refused (a different policy) and that refusal is the refusal. `:72-74`: under `d1-nonet` the apply succeeds (same policy); under any other profile it is refused. `containment/netguard-requirements.md:262-267` (Composition, Stacking): only the same compiled policy stacks; the gate probes under `d1-nonet` and refuses elsewhere. `containment/c/d1netgate.c:4-5` and `d1-server/crates/d1-recomp/netgate_profile.rs:7`: "same bytes" is now "same policy". The grep over `CLAUDE.md`, `containment/*.md` and `spec/03-runtime/03.2-recomp-runtime.md` found no other hit. `CLAUDE.md` at HEAD was already correct. |
| M3 | `containment/go/cgate_test.go:118` `TestBuiltGateStacks`: each built `d1-oracle` and `d1-recomp` runs under `sandbox-exec -p` with the Go-normalized policy (exit 0, no REFUSED), then under it plus `selectiveAllowance` (exit 2, "its profile did not apply"). With neither binary built it fails, naming the cargo command. Listed in `containment/README.md:78`. |
| M4 | Measured 2026-10-17 (lead session, after an `emit` of the 56578 eboot): `d1-recomp run --seconds 2` exits 4 (the runtime's time limit) with no REFUSED line, bare and under `d1-nonet`, so the second apply in `d1run_start` stacks on the first. See below. |
| S1 | `containment/go/cgate_test.go:82` `TestCGateDescriptors`: no extra descriptors gives exit 0; a socket at descriptor 3 gives exit 2 naming `fd 3: socket`. `:98` `TestCGateWrites`: the full policy gives exit 0; the policy minus every `file-write*` line gives exit 2 naming `write <root>/CLAUDE.md: allowed`, with the `/private/tmp` write control quiet. |
| S2 | `containment/README.md:1`: dated at 37e3cca. `:94-97`: rows for the three astra reviews, their response file and this review, with the commits that acted on each. `:111-112`: a binary built before a `game.sb` change is refused under `d1-nonet`, so rebuild after any change. |

Not changed, for the owner: `containment/netguard-requirements.md:27` and `:47` (decision record
point 2) still say the C file is "proof only" and "does not apply a profile". The review did not
name them, they are the owner's decision text, and the "interim now" paragraph under point 3
records that the gate applies. Whether point 2 should be amended is the owner's call.

## Controls

Run outside the agent sandbox after `cargo build --release -p d1-oracle -p d1-recomp`.
`go vet ./...` is clean and `gofmt -l .` is empty.

```
go test -count=1 -v ./...   26 passed, 0 skipped (23 before; 3 new)
```

## M4 (measured 2026-10-17 by the lead session)

`d1-recomp emit --out $TMPDIR/d1-emit-56578` (146 units, 374 s, 0 failed; the C is game code and
stays in the per-user temporary tree), then outside the agent sandbox, stdin `/dev/null`:

```
d1-recomp run --program $OUT --workdir $OUT/work-bare  --seconds 2 --log $OUT/run-bare.log    exit 4, REFUSED lines: 0
d1-nonet d1-recomp run --program $OUT --workdir ... --seconds 2 --log $OUT/run-nonet.log       exit 4, REFUSED lines: 0
```

Exit 4 is `on_alarm` in `runtime/d1run.c` (the `--seconds` limit): the game ran, so `d1run_start`'s
`d1_netgate("d1run")` applied the policy a second time in a process that had already applied it in
`main`, and under `d1-nonet` a third time. The refusal path for a differing policy is
`TestBuiltGateStacks` (exit 2 under the policy plus one allow), in the same suite.

## Commit

The commit that adds this file is on top of 37e3cca, with the subject
"one-policy review: comments, docs, three C-gate controls (M1-M3, S1, S2)".
