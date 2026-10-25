# Netguard requirements: network containment for the recompiled game

**State (2026-10-16): DRAFT.** Written by Claude (fork session) for the owner. Review order:
main game agent (Opus) → GPT (implementer). Nothing is built against this yet.

## Why this exists

From M6 the recompiled game opens real sockets to our own local servers. It must never reach
anything else: not the internet, not the LAN, not DNS. This doc says what "contained" means,
how each claim is proven, and what the code has to look like so a human can check it.

The first attempt (`codex/game-network-containment`) found one real thing worth keeping:
**a Seatbelt `localhost` rule also admits this Mac's LAN IP**, and Seatbelt cannot name
`127.0.0.1` literally. So the game gets *no* network permission at all, and a separate broker
makes the loopback connections for it. That design stays. The code gets rewritten to the rules
below.

## Rule 1: one language for the sandbox

- **The sandbox is Go, and only Go.** The launcher, the in-sandbox gate, the broker, **the agent
  hook (Claude Code PreToolUse), any install or check tooling,** and every test are Go. Standard
  library only. No cgo. No Rust beyond the call sites (decision record below). (Hooks added
  owner, 2026-10-16 17:20; they were in no doc before.)
- **The game side is C, because the game is C.** One file, `netguard_client.c` (with its
  header), that the game runtime `#include`s. It only speaks the broker protocol. It does not
  decide policy. Budget: 200 lines (150 for transport, about 50 for `netguard_selftest()`).
  **Applies and proves (owner, 2026-10-17; replaces "proof only"):** the game process applies the
  one policy itself and then probes; a refused apply is a refusal. The launcher applies the same
  policy first, and only the same compiled policy stacks, so the apply is the admission check.
- **Go is the protocol's source of truth.** A Go test compiles the C client and runs it
  against the real broker, so the two cannot drift. GPT owns both ends of the protocol
  (one protocol, one implementer). The game agent calls the C file and never edits it.

### Decision record: languages and ownership (owner, 2026-10-16 17:20)

Decided by the owner, overriding every statement in this doc, `agent-containment.md`,
`spec/03-runtime/03.2-recomp-runtime.md` section 7 and `archive/agent-hooks-rust/README.md` that disagrees. The record behind
it: the owner's 11:29 question "should this sandbox be in rust or go?", the 11:31 answer ("a
security boundary nobody can read is weaker"; "a deliberate exception" to CLAUDE.md "worth writing
down ... rather than letting it look like drift"), the owner's 12:16 "this sandbox now has go C and
rust.... like no", and the owner's 17:20 instruction to make the docs consistent. The exception
was promised for CLAUDE.md at 11:31 and not written; a Rust launcher and hook were then built
between 15:08 and 15:27 under CLAUDE.md's Rust rule. That is the drift this record closes.

1. **Outside the game process: Go.** Everything that applies a sandbox, decides policy or guards
   the agent is its own program in Go, standard library, no cgo: the launcher, the broker, the
   agent hook, and any install or check tooling.
2. **Inside the game process: C.** One small file the runtime `#include`s and calls first in
   `d1run_start`. It applies the one policy and proves it; a refused apply is a refusal (exit 2),
   as is any probe that does not hold (owner, 2026-10-17; this replaced "proof only"). The three
   Rust binaries that run game code (`d1-recomp`, `d1-oracle`, `d1-replay`) call the same C
   function through one FFI line as the first statement of `main`. Budget as Rule 2.
3. **Rust: the call sites only.** `crates/d1-netgate` (lib.rs, hook.rs, install.rs, the three
   bins, callsites.rs; 2,442 lines with the C twin at b504d55) was the interim implementation.
   **Archived the same evening** at the owner's instruction ("remove/archive files that break the
   rules"): it is `archive/d1-netgate-rust/`, out of the workspace, and nothing depends on it. Its
   measurements (`spec/03-runtime/03.2-recomp-runtime.md` section 7) stand; they are facts about Seatbelt, not about
   Rust. Gone with it, until the Go pieces exist: the this-Mac-only gate (`enforce_local_only`,
   `require_loopback`) in the seven servers and tools, the `d1-nonet` and `d1-localonly`
   launchers, the `d1-agent-hook` hook, and the call-site drift test. Nothing those gated runs
   today: the servers and every host-socket run are on hold (section 7's banner).
   **The interim now** is `containment/c/d1netgate.c` alone. It applies the game profile to its own
   process and proves it. It is reached two ways: `d1run.c` includes it and calls
   `d1_netgate("d1run")` first in `d1run_start`; and `d1-recomp`, `d1-oracle` and `d1-replay`
   each compile the same file in (`build.rs`, the `cc` crate, `-DD1_REPO`) and call
   `d1_netgate(tool)` as the first statement of `main` through one `extern "C"` line, the point 2
   shape. Identical profiles stack, so a program gated at both places is contained once.
   Measured 2026-10-16 evening: `d1-oracle --help` and `d1-recomp --help` exit 0 outside the
   agent sandbox (stdin `/dev/null`) and exit 2 inside it.
   **Under the Go launcher (piece 2, `d1-nonet`) the gate applies the same policy again:**
   measured the same night and re-measured after the one-policy revision, `sandbox_init` stacks
   only under the same compiled policy; comments, line layout and a `REPO` parameter versus the
   literal path do not matter, one extra `allow` does (EPERM). So the launcher embeds `game.sb`
   and the C gate is compiled from the same file (`netgate_profile.rs`, the same normalization as
   `gate.Normalize`); the gate's apply is mandatory and a refused apply is a refusal (exit 2),
   which is the admission check: anything already sandboxed under a different policy, the agent
   sandbox included, cannot run game code. Inside the agent sandbox the apply is refused and the write
   probes fail (the repository is writable there), so a bare run from an agent still exits 2.
   One difference from the Rust crate: on Linux the call is compiled out (the gate
   is Seatbelt), where the Rust gate refused outright; the Linux gate is the inherited `unshare`
   launcher, as before. `d1-replay` does not build on macOS today for an unrelated reason
   (`d1-live`), so its gate is compiled but unmeasured.
   This rule is about the containment layer only. The game itself may be as much Rust as it
   wants (owner, same day).
4. **One policy.** The game profile is `containment/go/profiles/game.sb`, read by the owner.
   `d1_netgate::profile()` went with the crate. The launcher embeds `game.sb` (`profile.go`) and
   the C gate's `D1_NETGATE_PROFILE` is generated from the same file at build time
   (`crates/d1-recomp/netgate_profile.rs`, included by the three `build.rs` and `fntest.rs`), both
   through the same normalization. There is no second copy to drift. The C proof's probe list and
   `game.sb` are reviewed together, as one change.
5. **CLAUDE.md records the exception** to "a reusable tool is a Rust tool" (same commit). This
   doc owns the language rule; the other docs point here and do not restate it.
6. **The owner's review standard, restated:** the owner reads Go well, reads a 250-line C file
   acceptably, and does not read Rust. A boundary the owner cannot read does not ship.

**Owner constraints on the agent-side shape (recorded owner, 2026-10-16 17:20; the design is not yet made):**
* no control may depend on a recurring human check; the only standing check is the game's own
  REFUSED line at every start;
* `sandbox.excludedCommands` and the macOS firewall are system-wide and stay as they are;
* `codex exec` from a Claude session stays workable;
* protection covers the named procedure and containment files only, never directories; the Write
  tool keeps working everywhere else;
* the owner's decision page is the materials themselves (the CLAUDE.md text verbatim, the file
  list, the install commands), not a pointer to a document; and a `check` command is not a gate.

### Port plan (owner, 2026-10-16 evening): the Rust shape, in Go

* **Piece 1 (the profiles) is accepted** by the owner, 2026-10-16 evening.
* The owner reviews the **surfaces** (each profile, each binary's behaviour and refusal text), not
  every test.
* "What was in Rust was probably correct. It just needs to be in Go." The archived crate
  (`archive/d1-netgate-rust/`) is the specification for the Go pieces, and the Rule 2 order is
  restated to match it. Each piece is 200 lines or fewer excluding tests and stops for the owner:
  2. **`d1-nonet`**: the gate and the launcher in one Go binary (the Rust `d1-nonet` plus the
     parts of `lib.rs` it used): descriptor hygiene, apply `profiles/game.sb` through
     `/usr/bin/sandbox-exec -D REPO=...`, re-enter itself under the profile to prove it, then exec
     the command. `game.sb` becomes the measured profile (the text in `containment/c/d1netgate.c`),
     parameterized by the repository root, every rule commented; piece 1's additive Mach denies
     stay; its wholesale `process-exec` and `mach-lookup` denies and the broker-path allowance are
     deferred until the recompiled game is the only thing run under it (`d1-recomp` spawns `clang`).
  3. **`d1-localonly`**: the this-Mac-only launcher (the Rust `local_only_profile` as
     `profiles/local.sb`, the local probes, `require_loopback`'s bind check).
     **Built 2026-10-17, awaiting the owner's review** (`cmd/d1-localonly`, `profiles/local.sb`,
     `gate/local.go`, `gate/launch.go`; `reviews/RESPONSE-pieces-3-4-2026-10-17.md`). The bind check
     is not portable to a profile: Seatbelt admits a bind to 0.0.0.0 and the LAN address under
     `localhost` (measured, `TestLocalOnlyBinds`), so it is neither kernel-enforced nor probed; the
     macOS firewall is that control.
  4. **`d1-agent-hook`** with `settings` and `check` (the Rust `hook.rs` and `install.rs`), built
     to the owner's constraints above. It also owns the launcher's entry contract (astra, piece 2
     review, finding 3): a launcher started with a socket on stderr or with `GODEBUG`, `DYLD_*`
     or similar variables set can write or run code before its `main`; the launcher scrubs those
     for the command it runs but cannot protect its own startup, so the hook path must start it
     with clean stdio and environment.
     **Built 2026-10-17, awaiting the owner's review** (`cmd/d1-agent-hook`, `hook/`; the owner's
     install steps are in `containment/README.md`, "Install (owner)"). The entry contract it holds:
     the launcher form adds only `D1_*` variables (never `D1_NET*`) to the command line and no
     redirection; what Claude Code's own shell environment and descriptors carry is stated in
     `reviews/RESPONSE-pieces-3-4-2026-10-17.md`.
  5. broker, 6. C client, 7. the assembled suite and README, as before.
* Go is standard library without cgo, so it cannot call `sandbox_check` or `bootstrap_look_up`.
  The launchers prove sockets, socket options, writes and exec by attempt; the Mach denies are
  proven by the C gate inside every game process and by the profile tests.

### What the C client must support (from `runtime/d1net.c`, reviewed by the game agent 2026-10-16)

`d1net.c` implements these libSceNet calls today, all over host sockets that are off unless
`D1_NET_SOCKETS=1`: Socket (stream, dgram), Bind, Connect, Send, Recv, Sendto, Recvfrom,
Sendmsg, Setsockopt, Getsockopt, Listen, Accept, SocketClose, plus the resolver (names from
`D1_NET_HOSTS` only). The client therefore needs:

- **TCP connect** to a service port, then send/recv as a byte stream.
- **UDP bind to a fixed local port** (the game binds 3074; observed 2026-10-16) and **sendto /
  recvfrom with the peer's port**: recvfrom must report the source port, because the game reads
  it. One bound UDP socket talks to more than one peer port.
- **Nonblocking behaviour on every socket**: the game sets nonblocking via setsockopt
  (`SO_NBIO`, 0x1200) and polls; it needs EAGAIN/EWOULDBLOCK, EINPROGRESS from connect, and
  SO_ERROR afterwards. No sceNetEpoll/select is implemented or has been seen called. The
  simplest shape that gives all of this for free: **every game socket is backed by one host
  file descriptor** that the client can read/write nonblocking and close (for example one Unix
  socket to the broker per game socket, UDP datagrams framed with the peer port).
- **Not needed now:** listen/accept (the HLEs exist but no call has been seen; the client has
  no listen/accept, and `d1net.c`'s Listen/Accept HLEs refuse with a logged EOPNOTSUPP until a
  real call is observed and this doc is amended), multicast
  (the game tried SSDP 239.255.255.250:1900; refusing it is correct), STUN to outside
  addresses, IPv6, raw sockets.

**Addressing by port only is fine for the game side.** `d1net.c` already maps every address in
10.209.0.0/24 and 127.0.0.0/8 to 127.0.0.1 at the *same port*, so port is already the only
thing that selects a service. The known limit (true today, not new): two services that share a
port (for example several HTTPS hostnames on 443) cannot be told apart by the broker; the
server behind that port must demultiplex them (SNI or Host header). Do not add an address
field for this.

**Integration on the game side (the game agent's work, not GPT's):** `d1net.c` replaces its
host-socket calls with the client's, and refuses everything when the broker variable is absent,
as it refuses everything without `D1_NET_SOCKETS` today.

## Rule 2: written for a human to review

The owner reviews this in Go. If they can't read it, it doesn't ship.

- `gofmt` and `go vet` clean. One statement per line. No `if err != nil { return }` on one
  line, no semicolons.
- Functions of about 40 lines or fewer. Names spelled out (`brokerSocketPath`, not `bp`).
- A short comment above every function: what it does and why it is safe.
- Every refusal logs what was refused and why, in plain words.
- **Size budget, excluding tests: 500 lines of Go, 200 of C, and 30 per Seatbelt profile.**
  Every profile rule gets a comment. If the budget is too tight, cut features, not
  readability.
- **Delivered in reviewable pieces, in this order, with a stop after each for the owner to
  read:** (1) Seatbelt profiles, (2) gate, (3) broker, (4) launcher, (5) C client,
  (6) the assembled suite and README. Each piece is 200 lines or fewer **and ships with the
  tests that prove it**, run and shown passing, so nothing is accepted without executable
  evidence. Piece 6 only assembles them. No piece starts until the previous one is accepted.
- No speculative features: no config files, no plugins, no TCP listen, no IPv6 service
  transport, no internet play.

## Rule 3: every threat has a profile rule and a control

"N controls pass" is not evidence. Each threat below needs (a) the rule that blocks it and
(b) a control that proves the block. **Per launch** controls run inside the game's sandbox on
every launch, and any failure refuses the launch with status 2. **Suite** controls run in
`go test` and in `netguard controls`.

| # | Threat: the game reaches the network by... | Blocked by | Control | When |
|---|---|---|---|---|
| T1 | opening a socket directly: IPv4, IPv6, IPv4-mapped | game profile denies all `network*` | connect *and* sendto to `127.0.0.1`, `192.0.2.1` (documentation space, RFC 5737: nobody answers it, but if the sandbox were broken a packet could still head for the gateway), `::1`, `2001:db8::1`, `::ffff:127.0.0.1`, and the Mac's own LAN IP: each must fail with EPERM/EACCES | per launch |
| T2 | starting a child process that opens a socket | profile is inherited across fork; `process-exec` allowed only for the gate and the game binary | forked child: T1 probes are denied. Exec of `/bin/sh` is denied | suite |
| T3 | DNS through the system resolver | `mach-lookup` of resolver services denied; mDNSResponder socket denied | a lookup that **succeeds outside the sandbox and goes through the resolver service** must **fail inside**: the Mac's own `<LocalHostName>.local` name via the libSystem resolver (Go uses it on darwin without cgo; `GODEBUG=netdns=cgo` forces it). Not `localhost` or `broadcasthost`: libSystem answers those in-process from `/etc/hosts`, and they resolve even inside the sandbox [C, 2026-10-16]. The `.local` lookup reaches mDNSResponder through its Unix socket, not a Mach lookup: allowing all `mach-lookup` still fails it, and allowing only `/private/var/run/mDNSResponder` makes it succeed [C]. So the socket denial is the rule this control proves, and its deliberate break re-allows that socket, run only *after* T1 passes. A failing `.invalid` lookup proves nothing: it fails everywhere (RFC 6761). The suite runs the same probe unsandboxed to show it succeeds there. Connecting to `/var/run/mDNSResponder` is denied | per launch |
| T4 | handing the work to a system service (URL daemons, launching another app) | `process-exec` limited as in T2; `mach-lookup` of LaunchServices' open, database and launch-fallback services and the network daemons denied | exec of `/usr/bin/open` is denied. Lookup of each listed service is denied (the Mach probes run in `netguard_selftest()`, open question 3). No application launches and no document opens by any of five routes (`openApplication(at:)`, `LSOpenCFURLRef`, `open` with the default handler, the deprecated `launchApplication(at:)`, `open(_:withApplicationAt:)`), measured against the installed `game.sb` (owner, 2026-10-17, PASS). History: with the four LaunchServices names denied, a launch still succeeded through `com.apple.coreservices.quarantine-resolver`, now denied (`44d391d`; `reviews/REVIEW-claude-launchservices-2026-10-17.md`). **Accepted exposure (owner, option A, `0cd1e66`):** `com.apple.coreservices.launchservicesd` is allowed so the game window can become active and key (keyboard and mouse). The game process can therefore read the running-application list with bundle ids and bring another application to the front: information about the desktop and a focus nuisance, not an escape. `local.sb` keeps the launchservicesd deny | suite + per launch |
| T5 | asking the broker for something not allowed | broker: literal `127.0.0.1` only, separate allowlists for TCP peer, UDP peer, and UDP bind port; the protocol has no address or hostname field | unlisted port refused; wrong magic, unknown op, and oversized frame each refused; UDP from an unlisted source port dropped; connection limit enforced | suite |
| T6 | a bug in the broker itself | **the broker runs as its own process under its own profile**: Unix socket plus Seatbelt `localhost`. Its OS wall is "this Mac only": Seatbelt cannot narrow it to `127.0.0.1` (it also admits the LAN IP, see top), but traffic to the Mac's own address never leaves the machine. Narrowing to literal `127.0.0.1` is the broker code's job (T5) | at startup the broker probes `192.0.2.1` (off-machine) and must be denied, or it exits 2. No LAN-IP denial is claimed for the broker | per launch |
| T7 | an inherited socket descriptor | at the moment the gate execs the game, only fds 0-2 survive: every other fd is closed or close-on-exec (the Go gate must not close its own runtime's fds before exec; it relies on close-on-exec for those). Stdin/stdout/stderr must not be sockets. Same rule when the launcher starts the broker | a probe exec'd in place of the game lists its open fds: only 0-2. Launch with an extra inherited socket: not visible to the probe; with socket stdin: refused | suite |
| T8 | the sandbox silently not applying (deprecated `sandbox-exec`, bad profile, game started without the launcher) | gate refuses unless T1 denials hold; the runtime refuses all network if the broker variable is absent (`d1net.c` already refuses sockets by default) | gate run with no sandbox: exits 2. Runtime with no broker: every socket call refused | both |
| T9 | Seatbelt `localhost` meaning the LAN IP too | the game gets no `localhost` rule at all, only the broker's Unix socket | the game gate also probes the Mac's LAN IP (T1 list), which must be denied | per launch |
| T10 | macOS changing sandbox behaviour after an update | per-launch controls, not a one-time test | — | per launch |
| T11 | network code in the runtime outside the client (a future libSceHttp/Ssl/NpWebApi HLE, the renderer, a stray `socket()`) | only `netguard_client.c` may call socket APIs: it is compiled as **its own object**, outside the `d1run.c` #include chain, and `d1net.c` reaches the network only through the client's functions (no direct `socket`/`bind`/`connect`/`listen`/`accept`/`sendto`/`sendmsg`/`getaddrinfo`); the profile (T1) still blocks the rest | **per-object import audit, at every link:** `d1-recomp link` compiles `fnrt.c` (the runtime TU) and `netguard_client.c` separately with `-c`, then `nm -u` on `fnrt.o`, every lifted `.o`, and `libd1gfx.dylib` must list none of `socket`, `socketpair`, `bind`, `connect`, `listen`, `accept`, `sendto`, `sendmsg`, `getaddrinfo`; only `netguard_client.o` may. Any hit fails the link. Plus a source grep (cheap extra): the same names as calls, `syscall(`, and any `dlsym`/`dlopen` string naming one of them or `libsystem_networkd`/`Network.framework` (a dlsym'd `socket` would not show in `nm`; the runtime's existing `dlsym(h, "d1gfx_open")` is fine) appear in `runtime/` and `gfx/src/` only in `netguard_client.c` | every link + suite |
| T12 | a system service doing work for the game outside our sandbox (every Mach service the game looks up runs in its own process, unsandboxed by us) | `mach-lookup` is an **allowlist**, not a denylist: only the services the game actually needs, each with a comment saying why. The renderer needs Metal's (GPU, MTLCompilerService); **the window (`D1_WINDOW=1`, AppKit + CAMetalLayer, added 2026-10-16) needs WindowServer and the AppKit services on top**, so find the minimal set by experiment in both modes, headless and windowed | real `bootstrap_look_up` probes in `netguard_selftest()` (in `netguard_client.c`, C; see open question 3): each listed denied service fails, each allowlisted one the mode needs succeeds; the list is printed by `netguard controls` | per launch + suite |
| T13 | the profile being loosened to make the GPU work | the GPU path is part of every launch, not a special case | per launch with `D1_GFX` set: Metal opens a device **and** the T1 probes still fail, in the same launch | per launch |

Required positive control in the same launch: the gate pings the broker and must get a reply,
so that a refusal can't be mistaken for "nothing worked."

**Process-exec conflict (T2, T4) to resolve before integration:** `d1-recomp run` currently
execs `clang` at launch to link the game (`src/runner.rs` → `fntest::link_program`). Under the
T2 exec allowlist that fails. Fix on the game side, not by widening the profile: the game
agent splits linking into its own step (`d1-recomp link`, run outside the sandbox) so the
sandboxed `run` only loads the prebuilt `program.dylib` and execs nothing.

**Guest code cannot make host syscalls directly** [I]: the lifter emits C, and the runtime has
no syscall pass-through (no `syscall` in `runtime/*.c`); guest syscalls reach only HLE code.
That is an inference from a code search, not a control. The T1 profile is what actually
holds if it is wrong.

## Composition with the game's self-applied boot gate (decided 2026-10-16)

*(Updated the same evening: the Rust crate is archived (decision record, point 3). The
self-applied gate is now the C one in `containment/c/d1netgate.c`, with the same profile and probes,
called first in `main` of the three game-code binaries (compiled in by `build.rs`) and again at
`d1run_start`. The measurements below are unchanged.)*

The game agent built `d1-netgate` (d441732, a820b47, d95db03). Every binary that runs game code
applies the gate's profile to itself with `sandbox_init` as the first statement of `main`, then
probes and exits 2 unless every probe is denied. Nothing turns it off. The profile is
`deny network*`, plus Mach denies for named network delegates, plus exec denies for `open` and
`osascript`, plus `job-creation` (`agent-containment.md` lists them). Its network rule has no
Unix-socket exception, so the game can never open a *new* connection, not even to a broker
socket. It is not a wholesale Mach or exec deny; that is `game.sb`'s job (T4, T12).

Measured on this Mac by Claude [C], using a C probe that applies that exact profile to itself:

- a Unix stream connected **before** `sandbox_init` keeps working, in both directions;
- a fresh `socketpair(AF_UNIX, SOCK_DGRAM)` end passed over it with `SCM_RIGHTS` delivers whole
  datagrams;
- a **new** Unix connect, and a loopback TCP connect, both fail with EPERM.

Therefore:

- **The launcher hands the game one pre-connected control descriptor** (a socketpair end, at a
  fixed fd number named in the environment). The broker has no filesystem socket path, and the
  game's profile needs no Unix-socket exception. `game.sb`'s `BROKER_SOCKET` rule goes away.
- **Every game socket is a descriptor the broker passes over that control channel** with
  `SCM_RIGHTS`: a datagram socketpair end for UDP, and a stream socketpair end that the broker
  splices to the real TCP connection for TCP. Nonblocking I/O and close then work natively on
  each one.
- **T7 changes:** the fds that survive into the game are 0-2 plus exactly that control fd. The
  gate checks it is an unnamed `AF_UNIX` socket (`getsockname`), not an inet socket.
- `netguard_selftest()` sits **beside** the boot gate, not in place of it. The gate proves no
  direct sockets, the named delegates denied, and no inherited INET socket. The selftest proves
  the broker path and the wholesale Mach rules.

### Measured by the game agent 2026-10-16 [C], and what each means here

- **Stacking.** A profile containing `(deny process-exec)` cannot be applied on top of any
  existing sandbox (EPERM), and nothing can be stacked after one. Re-measured after the
  one-policy revision: only the same compiled policy stacks. The gate is compiled from `game.sb`,
  so under `d1-nonet` its `sandbox_init` succeeds and it probes; under any other profile the
  apply fails and the gate refuses (exit 2). A suite test runs the gate under `game.sb` and
  under `game.sb` plus one allow.
- **Inherited INET sockets.** A TCP socket connected before `sandbox_init` keeps working, so
  an inherited INET fd is an escape route. The gate now refuses them, and T7 stays the
  launcher's job.
- **Multicast join.** `IP_ADD_MEMBERSHIP` on a fresh UDP socket *succeeds* under
  `deny network*`, and the kernel then emits an IGMP report. Seatbelt does not stop it.
  **T14 (new):** the C client exposes no socket options, and `d1net.c` refuses all
  `IPPROTO_IP` options. Control: the T11 import/source audit also flags `setsockopt` with
  `IPPROTO_IP` outside the client, and a suite probe documents that the OS allows it.
  `d1net.c` refuses every `IPPROTO_IP` option and every TCP option except `TCP_NODELAY` (1c6348b).
  Under netguard the game's "TCP socket" is a Unix socketpair end, so `TCP_NODELAY` becomes a
  logged **no-op in `d1net.c`** (it returns success and applies nothing). The broker sets
  `TCP_NODELAY` on every real loopback TCP connection itself. The client API stays option-free.
- **`sandbox_check` gotcha.** The operation name is `"process-exec*"`. Plain `"process-exec"`
  answers -1 for every path, and reading -1 as "denied" fails open. If `netguard_selftest()`
  uses `sandbox_check`, test its result for exactly 0/1 and treat anything else as a failure.
- **Delegates under `deny network*` alone** stay reachable by `bootstrap_look_up`:
  nsurlsessiond, dnssd.service, launchservicesd, lsd.mapdb, appleevents, configd. Exec stays
  allowed too. This confirms T4/T12 need `game.sb`'s wholesale denies.
- **The window works with LaunchServices denied** (AppKit logs one harmless
  `_LSModifyNotification -50`). That is evidence for T12; the wholesale `(deny mach-lookup)`
  under the window is still untested.

## Open questions for the implementer (answer before piece 1)

1. **UDP framing vs nonblocking.** A UDP socket framed over a Unix *stream* breaks nonblocking
   reads: a poll can wake on half a frame, and the client then has to block or buffer. Prefer a
   Unix **datagram** socket per game UDP socket (for example, the broker creates
   `socketpair(AF_UNIX, SOCK_DGRAM)` and passes one end over the control stream with
   `SCM_RIGHTS`; Go's standard library has `syscall.UnixRights`). Each read is then one whole
   datagram, prefixed with the peer port. Verify by experiment that Seatbelt allows I/O on a
   received socketpair end while `network*` is denied. If it doesn't, say so before choosing
   another shape.
2. **The T3 DNS control in Go without cgo: resolved.** Go on darwin (build without `netgo`)
   calls libSystem's `getaddrinfo` through its own trampoline, no cgo needed
   (`internal/syscall/unix/net_darwin.go`, `net/cgo_unix_syscall.go`; checked against the
   installed Go 1.23.5). Pin it with `GODEBUG=netdns=cgo` and show in the suite which
   resolver ran.
3. **Who owns T13's control, and where the Mach probes live: decided (game agent, 2026-10-16).**
   Mach-lookup probes need `bootstrap_look_up`, which Go can't call without cgo, so they live in
   C in `netguard_client.c` as `int netguard_selftest(void)` (0 = every control held). The
   sandbox code stays Go-only. The runtime calls it first thing in `d1run_start`, on the process
   main thread, before the renderer loads and before `D1_WINDOW` hands that thread to AppKit. A
   nonzero result ends the run with status 2 before any guest code runs. T13 is the game
   runtime's: after `d1gfx_open` has a Metal device (and the window is up, when windowed), the
   runtime calls `netguard_selftest()` **again** and requires it to pass, so the GPU path and
   the network denials are proven in the same launch. The selftest must therefore be
   idempotent, quick (well under a second), and thread-safe to call from the game thread.
4. **TCP connect may complete synchronously.** The broker's dial is to loopback, so the client
   can finish the handshake inside Connect and return 0 or an error, instead of emulating
   EINPROGRESS. The game agent confirms the game tolerates that.

## Out of scope (stated so nobody assumes otherwise)

- Filesystem restriction. The game can write wherever the user can.
- Protecting against other unsandboxed programs run by the same user.
- The local servers' own network access. Each server needs its own containment before it
  runs. This is a separate item.
- Touching agents, agent settings, firewall rules, or anything system-wide. The launcher
  affects only the command it starts and that command's children.

## Done means

1. Every row of the threat table has its rule and its control, and the controls pass.
2. The size and readability budgets are met. `gofmt -l` prints nothing.
3. A one-page README containing the threat table with links to the exact rule and control
   for each row.
4. The owner has read and accepted each piece (Rule 2).
5. Claude (a different model from the implementer) independently builds it, reads every line,
   and runs the controls, including a deliberate break (for example, the profile with
   `network*` allowed) to prove the gate refuses. Only after that does `D1_NET_SOCKETS`, or
   its broker replacement, get used for a game run.
