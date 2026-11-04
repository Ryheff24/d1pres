# Containment decisions and superseded designs

Why this file exists: `agent-containment.md` carried three superseded designs and one "proposed
text" for a rule that has been in force since 2026-10-17, and agents read all of it as current. The
owner's words (2026-10-27, on `hook.go`): "theres a lot of conflicting information and old
procedures that while they are quoted out, cause drift". So the active doc holds only what is in
force, and the record lives here (audit 2026-10-31, item 6).

Nothing here is a rule. Every rule in force is in `agent-containment.md`, `CLAUDE.md` (which
`AGENTS.md` is a symlink to) and `netguard-requirements.md`, which owns the one-profile-text rule.

## 2026-10-16 17:20 — the owner's decision on languages and ownership

Launcher, hook and tooling in Go; the in-process proof in C; Rust only at the call sites; one
profile text (`netguard-requirements.md` is the decision record). The reason, in the owner's words:
they must be able to read the boundary they are trusting. The Rust gate crate was archived the same
evening at `archive/d1-netgate-rust/`, out of the workspace.

## Superseded: the self-applied Rust gate

> ⚠ Superseded in design (owner, 2026-10-16 17:20); the Rust crate archived the same evening. The
> self-applied Rust gate described below is history (`archive/d1-netgate-rust/`). The interim is the
> C gate alone, `containment/c/d1netgate.c`, which applies the game policy (compiled in from
> `containment/go/profiles/game.sb` by `build.rs`, the one source) and then proves it. The Go
> launcher `d1-nonet` applies the same policy first; the gate's apply stacks only under the same
> compiled policy, so a refused apply is a refusal (exit 2), which keeps game code out of any other
> sandbox, the agent's included.

What was retracted with it: "The gate is self-applied, so there is no launcher script." The launcher
applies, the game proves. What the gate measured and proves was unchanged by the retraction.

## Superseded: point 1's first wording, and its proposed replacement

Point 1 once read: "Game binaries sandbox themselves. Run them from a Bash call outside the agent
sandbox, because inside it they refuse by design." A bare run now refuses from Claude Code (stdin is
a socket, and stdio is checked), and so does a run inside the agent sandbox (no nesting), so the
wording was replaced. The replacement was carried in the doc as "Proposed text" from 2026-10-17
onward although the owner had approved it the same day by copying it into `CLAUDE.md`; it is point 1
of "Running The Game" there, and point 1 of the procedure in `agent-containment.md`.

## Superseded: `autoMode.environment` as the backstop

The intent was to put one line in `autoMode.environment` describing this Mac. The line that was
drafted (2026-10-16) is out of date in its first clause: game-code binaries no longer "run bare,
under their own boot gate". The 2026-10-27 review found the field holds another project's text
("Trusted repo: .../CSE521/HW/HW1"), and the classifier that admits sandbox-off calls reads it. The
open item is in the audit, not here: set it to this machine's own description, or leave it empty.

## Superseded: the drafted Rust hook's run form

> **Run form, for reference.** This is what the drafted hook admits
> (`archive/agent-hooks-rust/README.md`; it is not installed and awaits the owner): one plain
> command; optional `D1_*=value` assignments (never `D1_NET*`); the absolute path of the gated
> binary in `d1-server/target/release/`; and `--log FILE` instead of shell redirection, with no
> quotes, pipes, `;` or `$`.

The installed Go hook (`containment/go/hook`, `LauncherForm`) is what decides this now, and the form
it admits is in `agent-containment.md` and in `CLAUDE.md`'s command table.

## Superseded: point 6's "awaits the owner's review"

Point 6 ("nothing that touches a network runs bare") listed `d1-localonly` as built 2026-10-17 and
awaiting review, with the servers on hold until then. It was installed and is in force; the
standing exception is unchanged and is in the active doc: the containment's own suite applies its
own profiles and cannot stack under either gate, so the owner runs it.

## 2026-10-19 — every test is contained

"Tests are always ran inside containment" (2026-10-18), then "any test at all" (2026-10-19). Nobody
sorts tests into networking and not. The record of how that is enforced is in the active doc; what
changed on 2026-10-31 is that the hook refuses a test run inside the agent sandbox as well, instead
of only a sandbox-off one (audit N7).

## 2026-10-25 and 2026-10-27 — elevated models

"gpt sol 6.1, gpt 6 astra, claude 5.5, fable 5.1 - elevated; everything else - current limit",
then, on the pull request the same day, every Claude 5.5 model rather than Opus alone, and the
owner's sandbox-excluded programs for elevated models only. 2026-10-27: "mythos is elevated as
well" (`claude-mythos-5-1`). 2026-10-28: the read-only logs and profilers are open to every model.

## 2026-10-16 — named files only, and where that rule now stops

"Named files only, never directories" was the owner's rule for the protected list, so that nothing
is protected by accident. The 2026-10-31 audit found what it costs: `install.sh` runs
`go test ./...` and `go build` over `containment/go` in the owner's terminal, so a file **nobody has
listed yet** — a planted `hook/planted_test.go`, an edited `go.mod` — runs as the owner, and
`.claude/hooks/` and `.git/hooks/` run whatever is put in them. Four directories are therefore
protected as trees (`gate.ProtectedTrees`): `containment/go`, `containment/c`, `.claude/hooks`,
`.git/hooks`. Everything else stays a named file.
