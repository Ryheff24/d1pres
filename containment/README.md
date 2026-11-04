# The network-containment collection (state at 37e3cca plus the one-policy review fixes, 2026-10-16)

**State (2026-10-16 night):** Go pieces 1 and 2 built and under astra review; the C gate reviewed
twice and in use, now compiled from `go/profiles/game.sb` (one policy). Piece 3, the this-Mac-only
launcher `d1-localonly` with `go/profiles/local.sb`, and piece 4, the hook `d1-agent-hook`, are
built and await the owner's review (2026-10-17; `reviews/RESPONSE-pieces-3-4-2026-10-17.md`).
Installed by the owner 2026-10-16 21:34 with the script under "Install (owner)"; `d1-agent-hook check` reported every line OK (40 lines). Reinstall with the same script after any change under `containment/go`. The hook is live: it blocked this session's first commit attempt because the command text named a protected file with a `;` in it (the tripwire, working as designed).

⛔ **Open (2026-10-17 00:25):** `game.sb` and `local.sb` let a process launch any application and
open any document (measured by the owner; `reviews/REVIEW-claude-launchservices-2026-10-17.md`).
The one-line fix, a deny of `com.apple.coreservices.quarantine-resolver` in both policies plus the
name in the C gate's probe list, is staged in the lead session's `scratchpad/window2/` and awaits
the owner's copy, a rebuild of the three gated crates, and a reinstall. Until then the T4 row is
not met.

This is everything that makes up the containment plan: what each gate review reads, and the
owner's final review (gate 3) before the procedure is copied into `CLAUDE.md` and `AGENTS.md`.
Paths are relative to the repo root.

**Decision (owner, 2026-10-16 17:20):** languages and ownership are settled in `containment/netguard-requirements.md`
(decision record): Go outside the game process, C proof inside, Rust only at call sites, one
profile text. The Rust crate listed below was archived the same evening to `archive/d1-netgate-rust/`
(out of the workspace); the file list under "Code: the gates" is now a list of what is in the
archive, kept so the reviews it was written for still read. What runs today is the C gate below.

## What is being decided

Whether to copy the six-point procedure in `containment/agent-containment.md` ("Procedure part") into
`CLAUDE.md` and `AGENTS.md`. The procedure leans on the code below. Read the plan, then the code
it cites.

## Plan and procedure (read in this order)

| file | what it is | owner |
|---|---|---|
| `containment/agent-containment.md` | The rule, the six points of the procedure (point 6: three places, nothing runs bare), why, decisions | netguard session |
| `spec/03-runtime/03.2-recomp-runtime.md` §7 "Network containment" (lines 176–515) | Both gates and their profiles, the measurements, controls, runs, the launchers, follow-ons | game session |
| `archive/agent-hooks-rust/README.md` | The launchers and hooks: the root-owned anchor, rules, the owner's install steps and settings, the check list, what it does not stop | game session |
| `containment/reviews/RESPONSE-gpt-6.1-sol-2026-10-16.md` | Each GPT finding mapped to its fix, what is left, and the owner's decisions | game session |
| `containment/reviews/RESPONSE-claude-final-2026-10-16.md` | Each final-review finding mapped the same way | game session |
| `containment/netguard-requirements.md` | The netguard design (the future game-network path), T1–T14 | netguard session |
| `CLAUDE.md` "Non-negotiables" | The standing rules the procedure would join | owner |

## Code: the gates (was `d1-server/crates/d1-netgate/`; now `archive/d1-netgate-rust/`, not built)

| file | what it is |
|---|---|
| `src/lib.rs` | Both profiles (`profile`, `local_only_profile`, with `restrictions`, `writes`, `game_writable`, `local_writable`, `local_protected`, `LOCAL_PORTS`), apply, every probe (sockets, socket options, writes, delegates, exec, jobs, inherited descriptors from `/dev/fd`), `check`, `check_local_only`, `enforce`, `enforce_local_only`, `launcher_hygiene`, `require_loopback`. Tests are in the bottom module: the probe control, refusal, sabotage profiles, inherited sockets (fd 7, stdin, fd 500 under a low limit), local-only lookalikes, malformed profile, bind check |
| `src/hook.rs` | The `sandbox-off` and `protect` rules, `LAUNCHER_DIR`, `PROTECTED` (also used by the local-only write rules), `BARE_RUNNERS`, the root-ownership check, path resolution as the volume stores it (`real_path`, inode comparison), with tests |
| `src/install.rs` | `d1-agent-hook settings` (the block for `~/.claude/settings.json`) and `check` (the owner's one-command install check), with tests |
| `src/bin/d1-nonet.rs` | The no-network launcher (game runs): hygiene, gate, exec |
| `src/bin/d1-localonly.rs` | The this-Mac-only launcher |
| `src/bin/d1-agent-hook.rs` | The PreToolUse hook binary, and the `settings`/`check` commands; protected repo files from any session, the rest for sessions in, inside or above the repo; fails closed |
| `tests/callsites.rs` | Drift detection, not a boundary: every gated binary calls its gate first in its one `fn main`, every server checks its bind, nothing unlisted touches the network or runs Unicorn |
| `Cargo.toml` | Dependencies: `libc`, `serde_json` |

## Code: the gate in the recompiled game runtime (`d1-server/crates/d1-recomp/`)

| file | what it is |
|---|---|
| `containment/c/d1netgate.c` | **The gate, the only one now.** Applies the game policy (`D1_NETGATE_PROFILE`, generated at build time from `go/profiles/game.sb`) with `sandbox_init`, refuses any apply failure (only the same compiled policy stacks, so this is the admission check), and probes (sockets, `SO_REUSEADDR`, writes, delegates, exec, jobs, `/dev/fd`). Entry `d1_netgate(tool)`; exit 2 on any failure |
| `runtime/d1run.c` | `d1run_start` calls `d1_netgate("d1run")` first; the file is included at line 87 |
| `build.rs` (also `d1-oracle/build.rs`, `d1-replay/build.rs`) | Compiles `d1netgate.c` into the binary with the `cc` crate, `-DD1_NETGATE_PROFILE=<normalized game.sb>` and `-DD1_REPO=<repo root>`; reruns when `game.sb` changes; macOS only |
| `netgate_profile.rs` | `include!`d by the three `build.rs` and by `fntest.rs`: reads `containment/go/profiles/game.sb`, normalizes it exactly as `gate.Normalize` does, writes the C literal |
| `src/fntest.rs` (`link_program`) | Passes the same two defines when it links a function test |
| `runtime/d1net.c` | The game's libSceNet: every socket refused unless `D1_NET_SOCKETS` (never set); `hle_sceNetSetsockopt` refuses `IPPROTO_IP` options (T14) |
| `src/main.rs` (`extern "C"` + the first line of `main`; same in `d1-oracle` and `d1-replay`) and `--log` | The gate call, `d1_netgate(c"d1-recomp".as_ptr())`; `--log FILE` so a run needs no shell redirection |

## Code: gate call sites (one or two lines each)

| file | call |
|---|---|
| `d1-server/crates/d1-recomp/src/main.rs` | `extern "C"` + `d1_netgate(c"d1-recomp".as_ptr())` first in `main` |
| `d1-server/crates/d1-oracle/src/main.rs` | the same, `"d1-oracle"` |
| `d1-server/crates/d1-replay/src/main.rs` | the same, `"d1-replay"` (does not build on macOS today: `d1-live`) |
| `d1-server/crates/d1-recomp/runtime/d1run.c` | `d1_netgate("d1run")` first in `d1run_start` |
| the servers (`d1`, `d1-bap`, `shadnet-server`, `d1-forge`, `d1-responder`, `d1-harness`, `d1-activity-host`) | **no gate** since the Rust `enforce_local_only` / `require_loopback` were archived; they run under `d1-localonly` (piece 3, built 2026-10-17) and stay on hold until the owner accepts and installs it. Nothing restores the in-code loopback bind check: Seatbelt cannot narrow a bind to loopback (`TestLocalOnlyBinds`), so the macOS firewall is that control |

## Code: the Go containment (`containment/go/`)

| file | what it is |
|---|---|
| `profiles/game.sb` | **The game profile, the one source.** The measured rules, one per line, each commented. Piece 1 (accepted) rewritten by piece 2 to the measured text |
| `profiles/broker.sb` | Piece 1's broker profile; not in use until the broker (piece 5) |
| `cmd/d1-nonet/main.go` | **The launcher.** `d1-nonet CMD`: hygiene, apply the profile through `sandbox-exec`, prove it, run CMD. One REFUSED line, exit 2 |
| `profiles/local.sb` | **The this-Mac-only profile** (piece 3): outbound only to the servers' loopback ports, listen on this Mac, no IPv4/IPv6 socket options, the Rust delegate, exec and job denies, writes to temporary space, the repository and cargo's caches except the protected files (`gate.ProtectedFiles`) and every directory above one |
| `cmd/d1-localonly/main.go` | **The this-Mac-only launcher.** `d1-localonly CMD`: same shape as `d1-nonet`, with the repository root set at build time; refuses game binaries (exit 64) |
| `gate/gate.go` | The probes and the refusal line, shared by the launchers |
| `cmd/d1-agent-hook/main.go` | **The hook** (piece 4): reads the PreToolUse event, exits 0 (on to Claude Code's own permission flow) or 2 with one BLOCKED line; `settings` prints the block for `~/.claude/settings.json`, `check` reports the install facts |
| `hook/hook.go`, `hook/shell.go`, `hook/protect.go`, `hook/install.go` | The rules: the launcher form for sandbox-off Bash, game binaries never bare, the owner's excluded programs only from elevated models and only alone (`xcrun` only to query the SDK or start simctl, devicectl, xctrace without `--launch`; `security` only as `find-identity`), a Bash command naming a protected file only as a pure read (a spelling-based tripwire), edits of protected files refused (compared by device and inode), fail closed; the settings block and the check |
| `hook/matrix.go`, `hook/matrix_test.go` | **The access control matrix** (owner, 2026-10-25): who gets what, one row per capability, elevated models against every other model. `agent-containment.md` shows it verbatim; `TestAccessMatrix` runs probes of every row through the hook for both kinds of session and fails if a row, the hook or the doc disagree |
| `hook/elevated.go`, `hook/elevated_test.go` | Elevated tools by model (owner, 2026-10-25; `agent-containment.md`): sessions of gpt-6.1-sol, gpt-6-astra and every Claude 5.5 and Fable 5.1 model may also run process, memory and network inspectors, kill this project's processes and open repository files in VS Code with the sandbox off; the model is read from the harness's records, which no agent may edit. The test runs under `d1-nonet` from any directory |
| `gate/local.go`, `gate/launch.go` | The protected-file list, the this-Mac-only probes, and the launch steps `d1-localonly` shares (root check, account home, environment scrub, prove child) |
| `*_test.go`, `testdata/probe/` | The controls (none skipped outside the agent sandbox): profile tests (piece 1), launcher tests, sabotaged profiles, descriptors, write exclusions, and the C gate compiled with the embedded policy: admitted under it, refused under it plus one allow, refused naming a missing delegate, an inherited socket at fd 3, or a writable `CLAUDE.md`. `TestBuiltGateStacks` runs the built `d1-oracle` and `d1-recomp` under the policy (exit 0) and under it plus one allow (exit 2), so the Rust and Go normalizers are checked against each other; it fails if neither binary is built |

Reviews of piece 2: `reviews/REVIEW-gpt-6-astra-go-nonet-2026-10-16.md` and what followed.

## Reviews so far

All of them are in `~/Downloads/d1-security-review-2026-10-16/`. That bundle is a snapshot from
before the gate was hardened, not current code.

| review | covers | acted on |
|---|---|---|
| `REVIEW-claude-2026-10-16.md` | First review: F1–F8 | d95db03 and earlier |
| `REVIEW-claude-local-only-gate-2026-10-16.md` | The this-Mac-only gate, six items | 59d64bd |
| `REVIEW-claude-agent-hooks-2026-10-16.md` | Hooks and callsites, seven findings | d7c361f |
| `containment/reviews/REVIEW-gpt-6.1-sol-2026-10-16.md` | Gate 1: the GPT 6.1 sol xhigh review, twelve findings | 8e836b4, eacbb4d; mapped in `RESPONSE-gpt-6.1-sol-2026-10-16.md` |
| `containment/reviews/REVIEW-claude-final-2026-10-16.md` | Gate 2: the final review, ten findings, three blocking | b504d55; mapped in `RESPONSE-claude-final-2026-10-16.md` |
| `containment/reviews/REVIEW-gpt-6-astra-c-gate-2026-10-16.md` | The C boot gate, seven must-fix items | 26382bb; mapped in `RESPONSE-gpt-6-astra-c-gate-2026-10-16.md` |
| `containment/reviews/REVIEW-gpt-6-astra-c-gate-2-2026-10-16.md` | The C gate re-review: two false refusals, write coverage, drift controls | 50f0817; mapped in the same response |
| `containment/reviews/REVIEW-gpt-6-astra-go-nonet-2026-10-16.md` | Piece 2, `d1-nonet`: policy provenance and admission under another sandbox (reviewed at 76995a5) | 37e3cca |
| `containment/reviews/REVIEW-claude-one-policy-2026-10-16.md` | The one-policy revision (37e3cca): M1–M4, S1, S2 | mapped in `RESPONSE-claude-one-policy-2026-10-16.md` |
| `containment/reviews/REVIEW-claude-launchservices-2026-10-17.md` | ⛔ T4 gap: app launch and document open succeed under `game.sb`; the quarantine-resolver deny closes it; option A (launchservicesd) acceptable after the fix | staged for the owner (window2), pending |
| `containment/reviews/REPORT-owner-in-the-loop-2026-10-17.md` | Not a code review: what the owner's turns changed, from the session logs (116 turns, 10 episodes) | owner's question, 2026-10-17 |
| `containment/reviews/REPORT-owner-in-the-loop-2026-10-18.md` | Not a code review: the same analysis for 2026-10-18 alone, read live (117 owner turns, 31 agent commits, the day in order) | owner's question, 2026-10-18 |

## How to run the controls

In your own terminal, not from an agent (a Seatbelt profile cannot be applied inside the agent
sandbox, so every Seatbelt test skips there), and **from the d1preservation checkout, not from
d1remote** (measured 2026-10-31 in the owner's terminal): the C gate's write probes name `design/`,
`d1-server/crates/` and `d1-server/crates/d1-recomp/src/main.rs`, which exist only there. Run from
d1remote those probes get `ENOENT`, which the gate cannot distinguish from `EPERM`, so it fails
closed and `TestCGateUnderPolicy`, `TestCGateDescriptors` and `TestCGateWrites` fail with "the
profile applied but did not hold" — the gate is correct, the tree is wrong. `TestBuiltGateStacks`
needs `d1-server`, which d1remote does not have at all. `hook`, `orkey` and `cmd/d1-orkey` pass in
either repo, so a hook-only change can be checked here; the boundary cannot.

```sh
cd containment/go && GOCACHE=$PWD/.gocache GOFLAGS=-mod=mod go test -count=1 ./...   # every control, none skipped
cd d1-server && cargo build --release -p d1-oracle -p d1-recomp                        # the gated binaries
target/release/d1-oracle --help < /dev/null; echo $?                                    # bare: the C gate applies and proves, exit 0
go run ../containment/go/cmd/d1-nonet target/release/d1-oracle --help; echo $?          # under the launcher, exit 0
```

A binary built before a `game.sb` change applies the old policy in a bare run and is refused
under `d1-nonet`. Rebuild after any `game.sb` change (`build.rs` reruns on it, but only when cargo runs).

Inside the agent sandbox the same binaries exit 2 with one REFUSED line: that is the positive
control. (The commands above replaced the archived crate's `cargo test -p d1-netgate` and
`d1-agent-hook check`, which no longer exist.)

Until the owner has installed the launchers and the hook ("Install (owner)"), agents do not run
the servers or game binaries.

## Install (owner)

In your own terminal, outside any sandbox. Nothing here is run by an agent.

**Where it lives (owner, 2026-10-25).** `containment/` and `CLAUDE.md` are kept in
github.com/Ryheff24/d1pres and change only by a pull request there. d1preservation's git ignores
both. After you merge one, run:

```sh
bash /Users/ryanheffernan/Documents/projects/d1preservation/containment/update.sh
```
`containment/update.sh` (protected, like `install.sh`) clones main fresh into a folder in your home
that no agent or contained program can write. It lists the files here that differ from main and
overwrites them with main's. It stops before writing anything if `containment/go` or
`containment/c` holds a file main lacks, because the build would use it. Then it runs the new
`install.sh`. With `check` it only reports. Its log is `runs/containment-update-*.log`.

**Always `update.sh`, not `install.sh` (audit 2026-10-31, N4).** `install.sh` runs `go test ./...`
and `go build` over whatever is in `containment/go` in your terminal, as you, so a file an agent
left there runs as you. `update.sh` checks main out over the working tree and stops on any file
under `containment/go` or `containment/c` that main lacks, which is the control that makes that
safe; it then runs `install.sh` itself. Run `install.sh` alone only when you have just read
`git status` for `containment/` yourself and it is clean:

```sh
bash /Users/ryanheffernan/Documents/projects/d1preservation/containment/install.sh
```
`containment/install.sh` (a protected file: read it first, it is short) runs every Go control, builds
the three binaries with this repository's root compiled in, installs them root-owned into
`/usr/local/libexec/d1-agent/` (sudo asks for your password), backs up `~/.claude/settings.json` to
`settings.json.before-d1-agent-hook`, merges the hook entry and the deny rules into it (keeping
everything already there, your `sandbox.excludedCommands` included; an earlier hook entry is
replaced, not duplicated), and ends with `d1-agent-hook check`: every line must say OK. Running it
again is harmless. The hook takes effect in new Claude Code sessions.

It builds and caches in a directory it makes in your home (`~/.d1-agent-install.*`, removed when it
ends), not in temporary space or in the repository: both launcher profiles allow writes under
`/private/var/folders` and under the repository, so a game or server process running during an
install could have replaced a built binary between `go build` and `sudo install`, or poisoned the
build cache (audit 2026-10-31, N5).

`settings` prints one `hooks.PreToolUse` entry (matcher `Bash|Edit|Write|MultiEdit|NotebookEdit`,
command `/usr/local/libexec/d1-agent/d1-agent-hook`), one `permissions.deny` Edit rule per
protected file and one per protected tree (`Edit(/<root>/containment/go/**)` and the other three).
`check` reports what it measured: the build's repository root; the directory and
each binary root-owned, closed to other writes, with their modes; the hook and deny rules in your
settings; each `sandbox.excludedCommands` entry one the hook knows; each protected file present and
each protected tree a directory.
It is a report, not the boundary. Rebuild and reinstall after any change under `containment/go`.
Keep the macOS firewall on: for a server bound to 0.0.0.0 under `d1-localonly` it is the only
control, because Seatbelt's `localhost` includes this Mac's own addresses, so the profile admits
that bind and connections to it from the network (`TestLocalOnlyBinds` measures the bind).

What the hook does (`hook/`): a Bash call with the sandbox off passes only as one plain command,
`D1_*=value ... /usr/local/libexec/d1-agent/d1-nonet <root>/d1-server/target/release/<game binary>
ARGS` or `.../d1-localonly /abs/program ARGS`, from a root-owned install; a game binary named
without `d1-nonet` is refused from any session; the read-only logs and profilers (`log show|stream`,
`xctrace export|list`, `sample`, `vmmap`, `footprint`, `malloc_history`, `metalperftrace
overview|listen`) pass for every model only as `ProfilerForm` (`hook/profiler.go`) admits: at
their own path, one line of literal words, listed options, this project's PIDs, no output files; a
command naming one of your other excluded programs
(`xcrun`, `xcodebuild`, `codesign`, `security`, `system_profiler`, `codex exec`, `copilot -p` never with `--allow-all*` or `--yolo`)
passes only as that one command, heredoc and redirections allowed, no `#` comment, nothing chained; a command
whose text names a protected file passes only as a pure read (no `; & > < $(` backquote, newline
or `tee` outside quotes, no word starting with `#`, no `$'`, `$"`, `${` or unquoted `(`, every `|`
segment a reading program), a spelling-based tripwire that an excluded
program run alone skips, so codex prompts may name those files; edits of the
protected files (`gate.ProtectedFiles` and `~/.claude/settings.json`) are refused from any
session. The Bash rules apply to sessions in, inside or above this repository. Anything it
cannot read is refused. If the hook binary cannot be started at all, Claude Code lets the call
through: `check` is how you see that.

## Owner edits to protected files (the window)

Measured 2026-10-17, first use: with the hook installed, an agent cannot write a protected file by any
route. The file tools are stopped by the `permissions.deny` Edit rules; sandboxed Bash gets
"Operation not permitted" on the same paths (Claude Code turns those deny rules into sandbox write
denials); a sandbox-off Bash write is refused by the auto-mode classifier and then at the permission
prompt; and the hook's tripwire catches a Bash command that names one with write syntax. So the
window is not a switch, it is a hand-off:

1. The agent writes each changed protected file, at its repository-relative path, under its
   scratchpad's `window/` directory (for example `window/CLAUDE.md`,
   `window/containment/go/hook/protect.go`), and tells the owner the directory's absolute path and
   what changed in each file.
2. The changes go to github.com/Ryheff24/d1pres as a pull request, from the owner's clone
   `/Users/ryanheffernan/Documents/projects/d1remote`, by a script the agent writes and the owner
   runs. The owner reviews and merges it there.
3. The owner runs `containment/update.sh`, which checks main out here and runs `install.sh` (it
   runs the controls, rebuilds, reinstalls root-owned and ends with `check`).

`sudo chmod 000 /usr/local/libexec/d1-agent/d1-agent-hook` disables only the hook's own refusals
(the tripwire and the launcher form); it does not open the files, so it is not needed for edits.
Undo it with `install.sh` or `sudo chmod 755 ...` and `check`.

**Auto mode and the launcher (live test 2026-10-17, finding 1).** Claude Code's auto-mode classifier
refused a sandbox-off launcher run as "Safety Bypass Flag" before the hook saw it; the same command
had passed in another session. That is Claude Code's, not the hook's. If it recurs, an allow rule in
`~/.claude/settings.json` for the launcher prefix, `"Bash(/usr/local/libexec/d1-agent/d1-nonet *)"`,
should skip the classifier while the hook still enforces the form; a leading `D1_*=` assignment may
defeat a prefix rule, so test it with and without one before relying on it.

**Allow rules (owner decision 2026-10-17, staged, not yet applied).** Outside auto mode every call
prompts; removing the classifier is not the fix. `containment/settings-allow.sh` (owner runs it, like
`install.sh`) backs up `~/.claude/settings.json` and adds three `permissions.allow` rules: the two
launcher prefixes and `Edit` under `d1-server/crates/d1-recomp/runtime/`. Deny rules are untouched
and win over allow, the hook still checks every launcher call's form, and the game sandbox is
unchanged. After running it, go back to auto mode and do the `D1_*=` prefix test the script prints.

---

# Owner quick reference

Run these in your own terminal.

## Agent hook

Check whether it is on (`-rwxr-xr-x` = on, `----------` = off):

```sh
ls -l /usr/local/libexec/d1-agent/d1-agent-hook
```

Turn it **off**:

```sh
sudo chmod 000 /usr/local/libexec/d1-agent/d1-agent-hook
```

Turn it **on**, then confirm every line says OK:

```sh
sudo chmod 755 /usr/local/libexec/d1-agent/d1-agent-hook
/usr/local/libexec/d1-agent/d1-agent-hook check
```

Off only stops the hook's own refusals. The deny rules still protect files, and the game sandbox
is unaffected. Use `install.sh` only after changing code under `containment/go`; it also turns
the hook back on.

## Watch the sandbox live

The system log does not record sandbox denials, so watch the packets instead.

Every packet, with the process that sent it:

```sh
sudo tcpdump -i pktap,all -k NP -n
```

Only the game (`eproc` also catches a system daemon sending on its behalf):

```sh
sudo tcpdump -i pktap,all -k NP -n -Q "proc =d1-recomp || eproc =d1-recomp"
```

Save a run for Wireshark:

```sh
sudo tcpdump -i pktap,all -k NP -n -w ~/d1-watch.pcapng
```

Live connections per process:

```sh
nettop -m route -p d1-recomp
```

During a run the filtered capture should stay empty. To prove the watcher works, run a
`curl https://example.com` and watch it with `proc =curl`. Pipes and socketpairs between our own
processes are not packets, so they never show.

## Inside the game sandbox (measured 2026-10-18)

- Pipes and socketpairs work.
- TCP connects fail with `EPERM`, including from child processes, which inherit the sandbox.
