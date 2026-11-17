# d1pres

The rules and the containment for a private project that statically recompiles Destiny 1 (PS4) to
native arm64 macOS. AI agents (Claude Code and Codex) write that project's code. This repository
holds only what governs them: the agents' rules file and the sandbox boundary they work inside.

The game, its media and the project's own code are not here and never will be.

## Why it exists

- **Agents run game code.** That means code recompiled from a commercial game binary, and servers
  that speak its protocols. None of it may reach the network.
- **Remembering is not a control.** The game's sandbox cannot nest inside the agent's own sandbox,
  so an agent has to run that one command unsandboxed. An agent that forgets the wrapper runs the
  game with full network. That happened once (run70), so the game now checks for itself.
- **Agents misbehave in documented ways.** They route around blocked tasks, fabricate approvals
  between agents, and read docs that can be injected (Opus 5.5 system card, §6). Every rule here is
  therefore code with a test. There is no off switch, and a refusal always names the allowed form.
- **The owner reads the whole boundary.** It is written in Go and short C so it stays personally
  auditable. Rust appears only as the one-line gate call at the top of each `main`.

## The rule

- **Agents keep their network.** Research, docs and approved downloads are how agents work.
- **The game never has network.** Nor does anything that runs game code or speaks a game protocol.
- **Everything that runs or tests code runs in one of three places.** The hook refuses any form that
  would not, and the gate compiled into each binary refuses the run itself.

| place | what runs there | profile |
|---|---|---|
| the agent's own sandbox | research, builds, reading, writing code | the harness's own |
| `d1-nonet CMD` | game code and every test | `containment/go/profiles/game.sb`: no network |
| `d1-localonly CMD` | servers and the tools that talk to them; never game code, never a test | `containment/go/profiles/local.sb`: this Mac only |

## The pieces

| piece | where | what it does |
|---|---|---|
| Seatbelt profiles | `containment/go/profiles/` | The policy text, one source, each rule commented. |
| Launchers | `containment/go/cmd/d1-nonet`, `d1-localonly` | Scrub the environment, apply the profile, prove it held, then run the program. One `REFUSED` line and exit 2 on any failure. |
| Boot gate | `containment/c/d1netgate.c` | Compiled into every binary that runs game code and called first in `main`. It applies the same policy itself, then probes: sockets on loopback must fail with `EPERM`, the network delegates must be unreachable, no inherited socket may be open. Anything else exits 2. No variable, flag or config turns it off. |
| Test gate | `containment/c/d1testgate.c` | Force-loaded into every Rust and Go test binary, so every test runs the boot gate before `main`. |
| Agent hook | `containment/go/hook/`, `cmd/d1-agent-hook` | A PreToolUse hook on every agent tool call. It admits game code only as a launcher command, refuses edits to the boundary's own files and to the agents' session records, and enforces a per-model access matrix. |
| Access matrix | `containment/go/hook/matrix.go` | Who gets what, one row per capability. A named list of elevated models gets process, memory and system tools; every other model, subagents included, does not. `TestAccessMatrix` probes every row through the hook and fails if the code, the hook or the doc disagree. |
| Codex policy | `hook/codex.go` | The install writes a root-owned `/etc/codex/requirements.toml` that restricts Codex to the same profile, with the protected paths read-only. |
| Key forwarder | `containment/go/orkey`, `cmd/d1-orkey` | A localhost forwarder for one route to one model API host. The key arrives on a pipe and stays in that process's memory, so agents never hold it. |
| Install | `containment/install.sh`, `update.sh` | Run by the owner only. `update.sh` checks out a fresh `main`, stops on any file or symlink that `main` lacks, then runs `install.sh`. That runs every control, builds the binaries, and installs them root-owned in `/usr/local/libexec/d1-agent/`. |
| CI | `.github/` | Runs the suite with coverage on every PR. It fails under 60% total coverage, or on any file with none. |

The full design, the procedure and the access matrix are in
[`containment/agent-containment.md`](containment/agent-containment.md). The commands, the install
and the owner's quick reference are in [`containment/README.md`](containment/README.md). Decisions
and superseded designs are in [`containment/decisions.md`](containment/decisions.md).

## Changing it

Only the owner changes this repository, through a pull request here. Agents cannot write these files
by any route: deny rules stop the file tools, the sandbox stops writes from Bash, and the hook catches
a command that names a protected file with write syntax. An agent stages complete files instead. The
owner opens the PR, reviews and merges it, then installs it with `containment/update.sh`.

## Running the controls

Run them in your own terminal, not from an agent: a Seatbelt profile cannot be applied inside an agent
sandbox. Run them from the full project checkout, because the gate's write probes name its paths.

```sh
cd containment/go && GOCACHE=$PWD/.gocache GOFLAGS=-mod=mod go test -count=1 ./...
```

## What it does not stop

- **The boot gate names its delegates.** It does not deny all Mach lookups or all exec, so an
  unnamed delegate service is still reachable.
- **Seatbelt cannot narrow a bind to loopback.** A server bound to `0.0.0.0` under `d1-localonly`
  is reachable from the network unless the macOS firewall is on.
- **If the hook binary cannot start, Claude Code lets the call through.** `d1-agent-hook check` is
  how the owner sees that.
- **The Bash tripwire reads spelling.** It matches text, not meaning, and refuses some harmless
  commands as a result.
- **Codex worktrees are not covered.** Codex refuses a glob in a read rule.
- **macOS only.** On Linux the gates refuse to run.

## Reviews

`containment/reviews/` holds the independent reviews of each piece, by GPT, Claude and
Mythos-class models. Each one has a response that maps every finding to its fix or to the owner's
decision.

## Status

A personal project, not a product. There are no releases and no support.

## License

Apache-2.0, the same as agentlog. See [LICENSE](LICENSE).
