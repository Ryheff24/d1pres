# Review: the one-policy revision (HEAD 37e3cca), 2026-10-16 night

Reviewer: Claude (this session), replacing the astra pass that the ChatGPT usage limit cut off.
Scope: `containment/go/` (launcher, gate package, profile, tests), `containment/c/d1netgate.c`,
`d1-server/crates/d1-recomp/netgate_profile.rs`, the three `build.rs`, `fntest.rs` (`link_program`,
`repo_root`), `runner.rs` (the `run` path also links through `link_program`), and the docs named below.

## Verdict

**Accept piece 2 with the must-fixes below.** The admission mechanism is sound as measured: one
policy, embedded in the launcher and generated into the C gate from the same file through the same
normalization; the gate's apply is mandatory, and only the same compiled policy stacks, so a refused
apply is the refusal. What is missing is (1) a control that the two normalizers agree on the built
binary, (2) two cheap C-gate controls, (3) comments and doc paragraphs that still describe the
proof-only design, including in `game.sb`, which the owner reads.

## Findings

### M1 (must-fix, docs) `containment/go/profiles/game.sb:2-3, 32-33`
The file's own comments are false at HEAD: line 2 says the measured profile is `D1_NETGATE_PROFILE`
in the C file and "a change here is a change there"; lines 32-33 say the two extra Mach denies are
"additive to the C profile" and that "the C gate probes only its own twelve". Now the C macro is
generated from this file and the C gate probes all fourteen names (`netgate_delegates[]`, and the
count check at `d1netgate.c:149-151` refuses if the file and the list differ). Failure scenario: the
owner reads the one file they are meant to read and learns the retired design. Fix: rewrite those
four comment lines (rules unchanged): this file is the one source, the launcher embeds it, the three
`build.rs` and `fntest.rs` generate the C gate's policy from it; every `(global-name ...)` here must
be in the C gate's probe list and the gate refuses when the counts differ.

### M2 (must-fix, docs) stale "probes decide" paragraphs
- `containment/agent-containment.md:61-63` ("Inside the agent's own sandbox `sandbox_init` fails
  ..., so the probe sees an open loopback and refuses") and `:69-71` ("Under netguard's `game.sb` the
  gate's own `sandbox_init` is refused ... so the gate's probes decide. They pass as long as
  `game.sb` is at least as strict."). At HEAD a refused apply is itself the refusal, and under
  `d1-nonet` the apply succeeds because it is the same policy. Rewrite both bullets.
- `containment/netguard-requirements.md:264` ("`sandbox_init` therefore fails and its probes
  decide"): same correction, in the Composition section.
- `containment/c/d1netgate.c:4-5` says "the same bytes are already applied"; say "the same policy".
- `d1-server/crates/d1-recomp/netgate_profile.rs:7` "apply the same bytes": same wording fix.
- Grep the five docs (`CLAUDE.md`, `containment/*.md`, `spec/03-runtime/03.2-recomp-runtime.md`) for
  `probes decide`, `probes are what holds`, `proof-only`, `when it can`, `byte-identical`,
  `identical text`, `same bytes` and fix every remaining hit in place; leave struck-through or
  explicitly retracted history alone.

### M3 (must-fix, test) no control that the Rust and Go normalizers agree
`gate.Normalize` (Go) and `netgate_profile` (Rust) are two implementations of one transformation.
I traced both by hand (split on `\n`, cut at first `;`, trim Unicode whitespace, join with nothing,
replace the one `string-append` expression; CRLF, non-ASCII and `;` inside a rule behave the same in
both) and they agree, and the built `d1-oracle` exits 0 under `d1-nonet`, which is the empirical
proof. But nothing in the suite would notice if one side changed. `cgate_test.go` compiles the C
gate with the *Go* text, so it cannot see a Rust divergence. Failure scenario: someone edits
`netgate_profile.rs`, the bare run still passes (the gate applies whatever it was built with), the
suite is green, and the next run under `d1-nonet` exits 2 with "its profile did not apply", or worse,
a future change to `game.sb` is normalized two ways. Fix: add `TestBuiltGateStacks` in
`cgate_test.go`: for each of `<repo>/d1-server/target/release/d1-oracle` and `.../d1-recomp`, if the
binary exists run `sandbox-exec -p Normalize(GameProfile, repositoryRoot) -- BIN --help` with stdin
`/dev/null` (use `run`), require exit 0 and no `REFUSED`; then under the same policy plus
`selectiveAllowance` (with `listenSelective`) require exit 2 and `its profile did not apply`. If
neither binary exists, fail (not skip) with the cargo command from the README, since a skip is a
silent pass. Add the test to the README's control list.

### M4 (must-fix, measurement) the second apply in `d1run_start` is unmeasured since the change
`d1-recomp` applies the policy in `main` and again in `d1run_start` (`runner.rs:60` includes
`d1run.c`, which includes the gate; `link_program` passes the same two defines). Same-policy stacking
in one process was measured with the old Rust gate, not with this policy. Measure once:
run `d1-recomp run` (or `fntest`) against an existing emitted program directory if one is present
under `d1-server/target` or `runs/`, bare and under `d1-nonet`, and record exit status and the first
line of stderr in the response file. If no emitted program exists, say so in the response: unmeasured.

### S1 (should-fix, test) two C-gate controls missing
The Go prove step has sabotage and inherited-socket controls (`TestNonetSabotage`,
`TestNonetInheritedSocket`); the C gate has only the admission and Mach controls. Add, reusing
`buildCGate`, `run`, `removeLines`, `socketFile`:
- `TestCGateDescriptors`: the helper under the policy with a socket at descriptor 3
  (`ExtraFiles`) must exit 2 and name `fd 3: socket`; the same helper with no extra files exits 0 in
  the same test.
- `TestCGateWrites`: the gate built with and run under the policy minus every `file-write*` line
  must exit 2 and name `write <root>/CLAUDE.md`; this exercises `netgate_writes` and its positive
  control (`/private/tmp` must read allowed).

### S2 (should-fix, docs) `containment/README.md`
Line 1 still dates the collection at b504d55. The "Reviews so far" table lacks the three astra
reviews (`REVIEW-gpt-6-astra-c-gate-2026-10-16.md`, `-c-gate-2-`, `-go-nonet-`), their response
file, and this review. Add rows with the commits that acted on each (`git log --oneline` has them).
Add one line under "How to run the controls": a binary built before a `game.sb` change applies the
old policy in a bare run and is refused under `d1-nonet`; rebuild after any `game.sb` change
(`build.rs` reruns on it automatically, but only when cargo runs).

### Notes (no action in piece 2)
- N1. On Linux the call compiles out (`#[cfg(target_os = "macos")]`); the decision record says so.
- N2. An agent with write access can edit `game.sb` or the C file and rebuild. That is piece 4's
  job (the hook), not the launcher's.
- N3. `locate()` accepts any directory holding `CLAUDE.md` + `containment/`. A fake root only
  widens writes to `<fake>/runs`; the real repository stays under `(deny file-write*)`. Fine.
- N4. `(allow file-write* (subpath "/private/var/folders"))` lets game code write the per-user
  cache tree. Accepted in piece 1; revisit when T2 (exec allowlist) lands.
- N5. `cleanEnvironment` cannot protect the launcher's own pre-main startup; documented in code.

## Answers A-F

A. Sound as measured. Bare: the gate applies the policy and probes. Under `d1-nonet`: same policy,
stacks, probes. Under anything else (the agent sandbox included): EPERM, exit 2. A stale binary
applies an older reviewed policy bare and is refused under the launcher (S2 documents it). Tampering
is N2. Linux is N1.
B. Equivalent for every input I could construct; untested in the suite (M3).
C. Every probe is fail-closed: unexpected errno, success, uninspectable fd, missing required path,
`sandbox_check` error all add an item; the entry refuses at once on a failed apply; `_exit(2)` on
every refusal path; fd 2 socket exits silently. The one false-refusal path is a socket on stdin from
a bare Claude Code run, which is the documented rule (stdin `/dev/null`), and the launcher handles
it. `getpwuid` works because the libinfo deny is not in `game.sb`.
D. Hygiene (stdin, CLOEXEC, stdout), env scrub, prove child, exec of `/usr/bin/sandbox-exec` with
the same text. CMD re-exec, symlinks, PATH, TMPDIR, inherited fds and a fake root give nothing: the
policy is kernel-applied and CMD inherits it.
E. Missing: M3, S1. Windows: every existing control pairs its positive and negative in one test.
F. M1, M2, S2.
