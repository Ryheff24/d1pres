# PR #9 against the original containment reviews

Date: 2026-11-03. Recommendation: **request changes**.

## Scope and evidence

Reviewed [PR #9](https://github.com/Ryheff24/d1pres/pull/9), head
`a39234934a8577f99db8eca7d90b447d5d915852`, against base
`3c5b28153793c3d17318e9732a42a23e4e545a78`. The local checkout matched the PR head
and was clean during the review.

Original findings:

- [2026-10-31 audit, N1–N9](/Users/ryanheffernan/Documents/projects/d1remote/containment/reviews/REVIEW-mythos-audit-2026-10-31.md).
- [2026-10-27 review, F1–F8 and Cursor handling](/Users/ryanheffernan/Documents/projects/d1remote/containment/reviews/REVIEW-mythos-containment-2026-10-27.md).

The review combined source inspection with decision-only probes of `hook.Decide`
and `hook.ProtectedTarget`. Probe commands were strings supplied to the hook;
they were **not executed**. Filesystem checks used a temporary synthetic repository,
not game files or real protected files. Bash events carried `model: gpt-6.1-sol`;
the out-of-scope cases also carried `dangerouslyDisableSandbox: true`.

The macOS coverage workflow for this head reported success
([run 41248177453](https://github.com/Ryheff24/d1pres/actions/runs/41248177453)).
Its configuration skips `TestCGate*` and `TestBuiltGateStacks`, which require the
d1preservation checkout. The full local Seatbelt suite, game code, servers, and
installation were not run. This review does not establish the state of the installed
hook or host configuration.

## Executable regression tests

The follow-up adds [containment_regression_test.go](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/containment_regression_test.go),
with one `TestContainmentRegression` group per finding. These tests assert the intended
security behavior: unsafe forms must be refused and allowed controls must pass.
They have no expected-failure switch or skip, and are included automatically in
the existing hook package and coverage workflow. Production hook code was unchanged when they were
added; the fixes followed, and they now pass (see "Fixes" below).

The hook package was compiled with `go test -c` in the agent sandbox, with a fresh
temporary build cache and `GOPROXY=off`. The compiled binary then ran through the
installed `/usr/local/libexec/d1-agent/d1-nonet`, selecting `-test.run TestContainmentRegression`.
The launcher ran with the d1preservation working directory so its required root
probe paths existed. The regression fixtures remained in temporary space.

Observed on 2026-11-03: exit 1 from the tests, **14 failing leaf cases, 15 passing
control cases, no skips**. All five finding groups failed for the documented gaps;
there was no launcher refusal or fixture-setup failure.

| Test group | Unsafe cases failing | Controls passing |
|---|---:|---:|
| `CodexOptions` (R1) | 3 | 3 |
| `OutputExpansion` (R2) | 1 | 3 |
| `WorktreeCase` (R3) | 6 | 3 |
| `RelativeScope` (R4) | 3 | 3 |
| `TestWrapper` (R5) | 1 | 3 |

R3 checks `Edit`, `Write`, and `apply_patch` for each spelling, confirms file
identity with `os.SameFile`, and checks that an ordinary file in the same worktree
remains editable. R1 and R2 use an elevated session so model restrictions cannot
hide argument-check failures. R4 sets both session directories outside the fixture
repository. Commands and patches are hook inputs only; none is executed or applied.

These are deliberately failing regression requirements against the reviewed
implementation. They must turn green when the fixes land, without removing the
unsafe cases or weakening their expected refusal. No test covers the separately
deferred host configuration, server gates, or missing imports in d1preservation.

## Fixes (2026-11-03, later the same day)

R1 to R5 are fixed in the hook; the regression tests above are unchanged and pass. A
`SiblingForms` group was added beside them for the same gaps in neighbouring spellings: 20 unsafe
cases and 10 admitted controls (the owner's own codex line among them).

| Finding | Fix |
|---|---|
| R1 | `shellArguments` (shell.go) reads the excluded program's line as bash hands it over: quotes removed, redirections apart, each word marked when an expansion is left in it. `codexForm` reads options as clap does (`-sVALUE`, `-s=VALUE`, `-hsVALUE`, `--name=VALUE`), refuses any option not in codex exec 0.160.0's `--help`, refuses `--enable`/`--disable` like the `-c features.NAME` they stand for, and refuses any non-literal word before `--` except `-C "$PWD"`. |
| R2 | `-o` takes only a literal path, so `$HOME/.zshrc` and `~/...` are refused. The same rule now covers redirections (`redirectsInRepository`): a spelled-out path in the repository that is not protected, `/dev/null`/`stdout`/`stderr`, or `$TMPDIR/NAME`. `-C`/`--cd` and `--add-dir` must stay in the repository, since workspace-write writes there. |
| R3 | `worktreeTarget` (protect.go) trims the worktree prefix and matches `wt-` without case. |
| R4 | `reachesRepository` (hook.go) resolves every word, and every `cd`/`pushd` target, against the session's directories, with `~`, `$HOME` and `$PWD` expanded and file identity compared. With the sandbox off, a `cd` it cannot resolve or a path built on another variable applies the repository's rules (fail closed), and the refusal says why. |
| R5 | `commandWords` (hook.go) skips assignments and ordinary wrappers (`env`, `nice`, `timeout`, `time`, `nohup`, `xargs`, `sudo`, `command`, `exec`, `caffeinate`, `stdbuf`, `sh`/`bash`/`zsh -c`). It is used for test detection, for game binaries and excluded programs (`firstWordMatching`), and for `d1-localonly` (`runsTests`). |

How this was run: the hook package was compiled in the agent sandbox and run under `d1-nonet`
from the d1preservation working directory. Result: `TestContainmentRegression` had 59 leaf cases
passing, none failing or skipped. Every other hook-package test passed except `TestAccessMatrix`,
whose probe half passed; its doc comparison could not open `../../agent-containment.md` from that
directory, and d1-nonet refuses a d1remote working directory (no `design/`, no `d1-server/`). The
comparison was rerun as a plain program against d1remote's doc, and it matches. The outer suite's
`hook_test.go` (TestHookLauncherForm, Bash, Tripwire, Edits, Patches, FailsClosed, Harnesses,
ReachesIn) was run as an A/B, built once against this head and once against the fixes, with
fixture writes the game profile denies skipped. All 8 passed on both. The full containment suite
still needs the owner's `install.sh`.

R5's second half, in d1preservation, is closed by `cd178ff`: the seven ungated `tools/d1` packages
(cmd/d1-srv, cmd/roadmap-check, internal/perfscan, r01cmp, renderm, sched, viewdiff) import the
gate. The control was checked first: a gated binary inside the agent sandbox exits 2. Under
d1-nonet, `TestEveryTestPackageIsGated` passes, as do six of the seven packages. sched has one
failure, `TestEmitJobsDefaultMatchesTable`: it has been red since 2026-10-27 and waits on the
owner's protected `main.rs` change. The control already covered every test directory of the
module. It still counts an import from a file this platform does not build; a version that does
not, with a negative control, is staged for the owner. The other deferred items in the table below
are unchanged.

## Findings requiring changes

### R1 — P1: shell quoting bypasses the Codex option restrictions (N3)

Location: [shell.go:145](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:145),
with arguments constructed by `strings.Fields` in `ExcludedForm`.

The probe rejected the ordinary forbidden flag but admitted its quoted equivalent:

```text
REJECT  codex exec --dangerously-bypass-approvals-and-sandbox -
ADMIT   codex exec '--dangerously-bypass-approvals-and-sandbox' -
ADMIT   codex exec -sdanger-full-access -
ADMIT   codex exec -csandbox_mode=danger-full-access -
```

`strings.Fields` preserves shell quotes, while the shell removes them before passing
arguments to Codex. The option comparisons therefore miss the quoted flag. The
attached short-option spellings also receive no restriction from `codexForm`.
Their hook acceptance was measured; the submitted Codex commands were not run.

The quoted long flag alone leaves N3 open: Codex is a sandbox-excluded program,
and this flag disables the sandbox on which the exclusion relies.

Required correction: parse shell arguments before checking options, handle the
CLI's supported attached forms, and reject argument syntax that cannot be resolved
safely. Add controls for equivalent quoted and attached option spellings.

### R2 — P1: output-path expansion defeats the repository restriction (N2)

Location: [shell.go:188](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:188),
`outputInRepository`.

```text
ADMIT   codex exec -s read-only -o $HOME/.zshrc -
REJECT  codex exec -s read-only -o /private/tmp/outside-review.txt -
```

The check treats `$HOME/.zshrc` as a literal relative path below the repository.
The shell expands `$HOME` before the excluded Codex process receives it. That
process's output write is outside its tool sandbox, so the repository restriction
does not hold for the admitted argument. No shell profile was written during review.

Required correction: reject unresolved expansions in output destinations, or
validate the argument actually passed to the program without executing arbitrary
shell expressions. Apply the same argument normalization to quoted paths.

### R3 — P1: case variants bypass worktree protection (N6)

Location: [protect.go:165](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/protect.go:165),
`worktreeTarget`.

```text
REJECT  runs/wt-demo/d1-server/crates/d1-recomp/src/main.rs
ADMIT   RUNS/wt-demo/d1-server/crates/d1-recomp/src/main.rs
ADMIT   runs/WT-demo/d1-server/crates/d1-recomp/src/main.rs
```

All three spellings identified the same temporary fixture file, verified with
`os.SameFile` on this Mac. `underPath` compares without case, but `strings.TrimPrefix`
and the `wt-` prefix check are case-sensitive. The mixed handling loses the protected
repository-relative name and admits the edit target.

Required correction: preserve case-insensitive matching throughout worktree path
extraction and identification. Check existing-file identity and creation of missing
protected files under each case variant.

### R4 — P1: relative paths from another project skip the rules (N9/F2)

Location: [hook.go:137](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/hook.go:137),
the early scope return in `decideBash`.

With both session directories outside the synthetic repository, these sandbox-off
events produced different decisions:

```text
REJECT  cp x /absolute/path/to/repo/CLAUDE.md
ADMIT   cp x ../repo/CLAUDE.md
ADMIT   cd ../repo && go test ./...
ADMIT   cd ../repo && go run ./cmd/example-server
```

The scope extension looks only for the literal absolute `config.Root` in the
command. Ordinary relative paths into the same repository return before the
tripwire, test check, or sandbox-off launcher check. This reproduces the underlying
N9/F2 problem with a different, routine path spelling.

Required correction: account for resolved paths and directory changes when deciding
scope, and fail closed where a sandbox-off command's relationship to the repository
cannot be established.

### R5 — P2: ordinary wrappers bypass test detection (N7)

Location: [hook.go:233](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/hook.go:233),
`runsTestsInSandbox`.

```text
REJECT  go test ./...
ADMIT   env go test ./...
```

The detector recognizes `go` and `cargo` only as the first program after assignments.
An ordinary `env` wrapper is missed. The PR explicitly defers the seven missing
test-gate imports, so those packages still lack the in-binary backstop identified
by the original audit. The hook cannot yet support the broader claim that test runs
are automatically prevented inside the agent sandbox.

Required correction: recognize ordinary command wrappers and finish the missing
gate imports and package-coverage control in d1preservation.

## Original finding disposition

“Implemented” below describes reviewed source, not a fresh verification of the
installed host boundary. “Open” means this PR does not establish closure.

| Original finding | Assessment at the reviewed head |
|---|---|
| N1: writable Claude/git hooks | Implemented in source: protected trees, generated deny rules, and `local.sb` subpath denies cover both hook directories. |
| N2: excluded programs can overwrite protected files | Partial. The literal audit examples now encounter the tripwire; R2 shows the output restriction still differs from shell behavior. |
| N3: excluded programs can disable their own sandbox | Partial. Copilot is refused and ordinary dangerous Codex options are checked, but R1 bypasses the checks. |
| N4: editable rule/build inputs and poisoned cache | Protection of `containment/go`, `containment/c`, `.codex/hooks.json`, and the additional named files is implemented. The installer exports a fresh home-directory cache and update removes the old cache. However, `harness_test.go:41` still overrides helper-build `GOCACHE` to the checkout's `.gocache`; the claim that all control builds use the fresh cache is not established. No cache-poisoning exploit was performed. |
| N5: install artifacts in writable temporary space | Installer build and post-install control directories moved under `$HOME`. The suite's own helper directories still originate in its checkout through `TestMain`; this review did not verify installation under concurrent contained processes. |
| N6: unprotected worktree copies and missing containment files | Partial. Worktree-target checks were added, but R3 bypasses them. Copying containment, instructions, and Codex hooks during worktree creation is explicitly deferred. |
| N7: ungated test packages | Partial. Plain `go test`/`cargo test` execution is rejected, but R5 remains. The seven imports and the owning project's package control are not completed by this PR. |
| N8: model field bypasses proxy check | Implemented in source: the base-URL rule applies when a transcript is present and to calls naming a Claude model. |
| N9: sandbox-off calls from elsewhere | Partial. Exact absolute-root commands now enter the rules; R4 leaves relative forms open. |
| October 27 Cursor finding | Native event parsing, `Shell` aliases, and unsandboxed-harness handling were added. Native registration with `failClosed` and live integration remain unverified. |
| F1: server self-gates | Open. The active document acknowledges that the general server self-gate is outstanding. |
| F2: cwd-only scope | Partial; see N9 and R4. |
| F3: worktrees lack hooks/instructions | Open. Worktree provisioning changes are explicitly deferred. |
| F4: MCP execution tools escape hook matching | Open. `Matcher` remains `Bash|Edit|Write|MultiEdit|NotebookEdit`, rather than the proposed default-deny matcher. |
| F5: tripwire rejects ordinary reads | The reported quoted/escaped-pipe, `tee`-substring, and descriptor-merge cases are addressed. Decision probes admitted the representative ordinary reads below. This is not a proof of all shell syntax. |
| F6: unrelated `autoMode.environment` text | Open. The issue is recorded in the decisions document; this PR does not establish a host configuration change. |
| F7: refusals omit allowed forms | Improved in the reviewed tripwire, game, test, and sandbox-off paths. This review did not establish that every possible refusal includes a complete working alternative. |
| F8: leftovers and documentation drift | Documentation improved: superseded designs moved to `decisions.md`, and companion-script settings are recognized. Cleanup of the previously observed host leftovers is not established. |

## Positive controls and limits

Decision probes admitted these formerly problematic reads:

```text
grep -n -E 'alpha|beta' containment/c/d1netgate.c | head
grep -n steering containment/agent-containment.md
cat CLAUDE.md 2>&1 | head -40
```

The controls also confirmed rejection of the unquoted dangerous Codex flag, an
explicit absolute output path outside the repository, the lowercase worktree target,
the absolute protected-file copy, and plain `go test ./...`. Each corresponding
admitted variant is recorded above.

The review therefore supports concrete improvements, but does not support closing
N1–N9 as a group. R1–R4 are security-relevant gaps in the implemented fixes; R5 and
the explicitly deferred work leave automatic test containment incomplete. A green
coverage workflow does not cover these missing cases or replace the skipped
root-dependent controls.
