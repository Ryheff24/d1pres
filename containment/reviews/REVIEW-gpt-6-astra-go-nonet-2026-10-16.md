**Verdict: not yet.** The normal launcher path applies the reviewed restrictions before executing the command, and the descriptor strategy is appropriate for Go. The blockers are policy provenance and admission under an unrelated sandbox: the current probes cannot establish that the reviewed policy is active.

Read-only review of `76995a5`, including the requested history, three commit stats, both C diffs, prior reviews and response, and the specified Rust implementation. No files changed. I accept the supplied measurements; I did not rerun the suite or Seatbelt experiments. `gofmt -l` reported no changes. Counterexamples below are source-derived unless identified as supplied measurements.

**1. High — Runtime profile discovery loses the Rust launcher’s policy anchor.**

**Location:** [main.go:124](/Users/ryanheffernan/Documents/projects/d1preservation/containment/go/cmd/d1-nonet/main.go:124), especially `137–140` and `148–177`; application at `62–69`. Rust comparison: `archive/d1-netgate-rust/src/lib.rs:70–79,820–823`.

**What breaks:** A trusted launcher binary does not imply a trusted policy. Go accepts whatever `containment/go/profiles/game.sb` exists beneath the first directory containing two markers. An installed launcher outside the checkout falls back to the caller’s working directory. Neither the markers nor `os.Stat(profile)` establish authenticity, ownership, regular-file status, or immutable ancestry.

Rust’s policy was compiled into the launcher. Its repository location was also build-bound. Moving policy selection into a caller-influenced filesystem search is a substantive port change.

**Evidence:** `fakeRepository` already demonstrates that a copied launcher accepts another repository’s profile. More importantly, take the reviewed profile and append:

```scheme
(allow network-outbound (remote ip "localhost:48123"))
```

Every production network probe still targets port **9**. The write, socket-option and exec checks are unchanged. The modified profile can therefore admit a raw connection to a listener on the new port while satisfying the launcher’s probes. A local relay would extend that capability.

The trial only establishes that the selected profile applies. It does not authenticate its contents, and the subsequent invocation reopens the pathname.

**Smallest fix:** Keep `game.sb` as the reviewed source, but anchor the applied bytes to the trusted launcher: embed it at build time and pass that text to `sandbox-exec`, or load a fixed owner-installed profile with protected ancestry. Repository discovery may select `runs/`; it must not select policy. Hashing a mutable file and subsequently reopening it by pathname is insufficient.

This is a launcher trust mistake, not a Seatbelt limitation.

**2. High — “Already sandboxed” plus sampled denials admits weaker policies.**

**Location:** [d1netgate.c:248](/Users/ryanheffernan/Documents/projects/d1preservation/containment/c/d1netgate.c:248), through `275`; [main.go:30](/Users/ryanheffernan/Documents/projects/d1preservation/containment/go/cmd/d1-nonet/main.go:30), `91–115`; network probes at `gate/gate.go:38–95` and `d1netgate.c:131–163`.

**What breaks:** The C gate now accepts any existing sandbox that passes its samples. The Go binary’s publicly callable `--prove-then-exec` entry likewise skips mandatory profile application and proceeds to command execution after samples pass.

The profile in finding 1 is a concrete counterexample for both paths. It preserves every probed denial while allowing another network destination. No query needs to lie.

**What the status query means:** The supplied `sandbox_check(getpid(), NULL, 0)` measurement establishes sandbox presence. It does not establish the launcher’s identity, the profile’s identity, or blanket network denial. An unrelated permissive sandbox can legitimately return `1`; that is not spoofing the API.

The agent-sandbox measurement is therefore conditional: today its writable repository makes the gate refuse. Tightening those write permissions could make the same acceptance test pass without closing unprobed network access.

There is also a narrower error-path defect: when application fails outside the `inside` branch, `netgate_first` records the failure but **does not increment `netgate_failures`**. The comment calling this a “real error” does not match the decision.

**Smallest fix:**

- Make an unsuccessful mandatory application an unconditional refusal.
- Do not accept an unknown existing sandbox solely from these probes. To preserve both bare and wrapped C entry, generate both consumers from one exact policy representation and require successful identical reapplication; verify that composition with the supplied stacking constraint. Otherwise, retain refusal for unknown sandboxes until a trusted launch path supplies the admission guarantee.
- Remove the Go proof entry’s independent ability to execute arbitrary commands. One concrete Go-only arrangement is a proof-only child, followed by the outer launcher’s mandatory `sandbox-exec` of the command using the same immutable policy.

A flag, environment marker, parent name, or profile file found on disk is not authentication.

Under a **known successful application of the reviewed `game.sb`**, skipping redundant C application and running its probes is sound as a supplemental check. Generalizing that to *any* existing sandbox is the fail-open change since the second review.

**3. High for an untrusted invocation environment — Checking stderr in `main` is too late for runtime output.**

**Location:** [main.go:25](/Users/ryanheffernan/Documents/projects/d1preservation/containment/go/cmd/d1-nonet/main.go:25), environment forwarding at `69,115`.

**What breaks:** “A socket on stderr exits silently” holds for the supplied normal-environment measurement, not every invocation environment.

**Evidence:** `GODEBUG=inittrace=1` enables initialization diagnostics before `main.main`. The installed Go runtime enables this at [proc.go:196](/usr/local/go/src/runtime/proc.go:196), prints initialization records at `7294`, and writes them to descriptor 2 through [runtime.go:231](/usr/local/go/src/runtime/runtime.go:231). An inherited socket on stderr can therefore receive bytes before `gate.IsSocket(2)` runs.

Loader injection is the larger conditional version of this problem. Where the executable’s loader restrictions permit it, `DYLD_INSERT_LIBRARIES` can introduce code before `main`. Apple’s dyld gates these variables on executable security policy; an environment cleanup inside `main` cannot undo earlier initialization. [Apple dyld implementation](https://raw.githubusercontent.com/apple-oss-distributions/dyld/main/dyld/DyldProcessConfig.cpp).

**Smallest fix:** Establish and test a trusted **pre-exec** contract for the launcher: safe stdio and removal of runtime/loader control variables before starting it, with appropriate loader restrictions for the installed executable. Record this as an entry requirement for the hook/install path. Do not claim that an in-`main` scrub solves it.

This does not mean an environment variable can lift an already-applied kernel profile. The exposure precedes application.

**4. Medium — The suite does not establish several protections claimed by the surfaces.**

**Location:** [harness_test.go:68](/Users/ryanheffernan/Documents/projects/d1preservation/containment/go/harness_test.go:68), [nonet_test.go:98](/Users/ryanheffernan/Documents/projects/d1preservation/containment/go/nonet_test.go:98), [drift_test.go:23](/Users/ryanheffernan/Documents/projects/d1preservation/containment/go/drift_test.go:23), [policy_test.go:40](/Users/ryanheffernan/Documents/projects/d1preservation/containment/go/policy_test.go:40).

**What breaks and how we know:**

- **The new C admission behavior has no automated integration control here.** The harness builds two Go programs, not the C gate. Textual profile agreement does not exercise `d1_netgate`.
- **There are no Mach lookup tests.** The port-plan statement that profile tests prove those denies is unsupported by this suite.
- **The Claude-state and `.sb` exclusions have no behavioral fixtures.** Removing either exclusion alone leaves Go’s production write probes unaffected. Removing it from both profile representations also satisfies the drift comparison.
- **`TestUnixListening` can pass before bind or listen occurs.** Its helper calls `net.Listen("unix", ...)`. Go’s [listenStream](/usr/local/go/src/net/sock_posix.go:150) first sets `SO_REUSEADDR`; the new blanket socket-option deny rejects that operation. The helper accepts the resulting permission error as the expected listening denial. Its repository-based socket pathname also introduces filesystem denial as another possible cause.
- **`TestNonetRefusesUnappliedProfile` supplies no profile, but does not establish an unsandboxed process.** Inside an agent sandbox it inherits that sandbox.

**Smallest fix:** Add targeted controls:

1. Compile a small C helper from the actual gate through Go’s `os/exec`; no cgo is needed.
2. Exercise correct composition and a selectively weakened profile.
3. Use existing disposable fixtures for both write exclusions, testing write/create/rename/unlink with individual deliberate breaks.
4. Probe Unix bind/listen through raw syscalls at an otherwise writable disposable path, without preceding socket-option calls.
5. Exercise the named Mach policy queries, including deliberately removed denies.

**The biggest missing control is selective allowance, not another wholesale removal of `deny network*`.** Use an unsandboxed loopback listener on a non-9 port and the profile from finding 1. Establish the permitted connection safely, then require the admission mechanism to reject that policy. This directly distinguishes a known policy from samples that happen to pass.

**5. Medium — Close-on-exec errors are discarded, and the test checks sockets rather than the promised descriptor set.**

**Location:** [gate.go:241](/Users/ryanheffernan/Documents/projects/d1preservation/containment/go/gate/gate.go:241); `nonet_test.go:188–208`.

**What breaks:** `syscall.CloseOnExec` returns no error; its implementation discards the `fcntl(F_SETFD)` result. If setting the flag fails, a regular descriptor can survive without `NoInheritedSockets` noticing. The test’s successful `/usr/bin/true` run establishes that the socket did not trigger the proof; it does not enumerate the final command’s inherited descriptors.

**Smallest fix:** Use checked descriptor-flag operations and refuse on failure. Add an exec’d helper that reports surviving inherited regular descriptors as well as sockets, including a high descriptor above a lowered limit.

The two declared deviations themselves are otherwise fine:

- **Close-on-exec instead of close:** appropriate for Go; do not close runtime-owned descriptors underneath the runtime.
- **Skipping `EBADF` entries after `/dev/fd` enumeration:** appropriate for the enumeration’s already-closed descriptors. Other inspection failures still reach a refusal. This relies on the current startup path having no untrusted concurrent descriptor mutation.

**6. Low — The refusal surface does not always deliver its stated one-line, exit-2 contract.**

**Location:** [main.go:41](/Users/ryanheffernan/Documents/projects/d1preservation/containment/go/cmd/d1-nonet/main.go:41); `gate/gate.go:19–22`.

A broken stderr pipe can make Go terminate on `SIGPIPE` during `fmt.Fprintln`, before `os.Exit(2)`. The C gate explicitly handles this; Go does not. The command is also interpolated without quoting, so a newline in an argument can split the claimed single refusal line.

**Smallest fix:** Ignore `SIGPIPE` for best-effort refusal output and escape caller-controlled diagnostic fields. Describe usage exit 64 and command-execution exit 127 separately from containment refusal.

For **A, the remaining launcher boundary assessment** is:

| Surface | Assessment |
|---|---|
| Fresh direct network access | The reviewed `deny network*` blocks it, including child processes. The supplied curl result and raw-syscall suite support this. |
| Multicast socket options | `deny network*` alone has the recorded IGMP limitation. The separate blanket socket-option deny addresses it; the three harmless option probes are appropriate samples. |
| Inherited sockets | Persistent access is a known Seatbelt limitation. Replacing stdin, marking extra descriptors close-on-exec, checking stdout/stderr, and scanning after exec address the ordinary socket path. No broker-fd exemption remains. |
| Pipes and Mach rights | The fd scan neither authenticates pipe peers nor inventories Mach send rights. Ordinary captured output remains a deliberate communication channel. Existing rights and unlisted services remain limits of the interim design. |
| Procedure files, shell startup files, LaunchAgents | For this checkout and ordinary home paths, the blanket write deny covers them and their ancestors. Missing individual probes do not make those paths writable. |
| `/private/tmp/claude*` and `*.sb` | The final exclusions are present and correctly ordered after temporary-directory allowances. Behavioral exclusion controls are still missing; no alias/hard-link bypass is established by this review. |
| Other temporary inputs | Broad access to `/private/tmp` and `/private/var/folders` permits alteration of other writable same-user temporary inputs. This is a policy choice, not an unavoidable Seatbelt limit. The profile cannot promise that nothing written there will later be consumed unsandboxed. |
| Trial application | Useful diagnostics, not authorization. It runs only `/usr/bin/true`; it does not weaken the final process. Its claim that profiles cannot apply inside *any* sandbox contradicts the supplied identical-profile exception. |
| Re-exec and `exec.LookPath` | Argument-vector construction avoids shell interpolation. Command lookup occurs after containment. Selecting another executable through `PATH` does not remove the inherited profile. |
| Root validation | Canonicalizing the starting paths and rejecting writable temporary roots and unsafe characters is good. Marker discovery establishes layout, not trust. |
| Environment after application | `HOME`, `PATH`, startup variables and proxy variables cannot remove the profile. `$HOME` can redirect the write probe, so that probe is weaker than Rust’s account-database lookup. |

The deferred wholesale Mach and exec restrictions remain **accepted interim limitations**, not accidental omissions to reinstate blindly. Arbitrary exec does not itself escape inheritance; copied `open` functionality still encounters the profile. However, the named-service denylist provides no general guarantee against delegated work through other services. Applying before the target exec improves on a self-gate reached only after target initializers; those initializers can otherwise acquire persistent resources before `main`. [Chromium’s Seatbelt design](https://raw.githubusercontent.com/chromium/chromium/main/sandbox/mac/seatbelt_sandbox_design.md).

For **C, Rust-to-Go parity**, the material differences are:

| Rust behavior used by `d1-nonet` | Go result | Significance |
|---|---|---|
| Embedded policy; failed application always refuses (`lib.rs:70,820`) | Runtime profile file; callable proof/exec mode | Findings 1–2; substantive losses. |
| TCP/UDP loopback and TCP own-address probes (`776–784`) | Preserved | Fine. Do not attribute the separate Rust local-only probes to this launcher. |
| One harmless socket-option probe | Three option probes | Improvement. |
| Real lookup attempts for twelve delegates; job-creation query (`688–718`) | Neither in Go | C supplies exact policy queries for game binaries, but arbitrary commands receive no such per-launch check. The claimed suite compensation is missing. |
| Account-database home and explicit shell, LaunchAgents, settings, harness-state and source-file probes (`792–800`) | `$HOME` plus broader repository paths | Reduced coverage. The current blanket profile still protects these locations; the C gate restores much of the explicit coverage for game binaries. |
| Close descriptors above 2 | Mark close-on-exec | Correct Go adaptation, subject to finding 5. |
| Environment-selected Unix-socket exemption (`748–768`) | No exemption | Stronger; do not restore it before authenticated broker construction exists. |
| PATH-based command execution | `exec.LookPath` and `syscall.Exec` | Equivalent boundary behavior; Go’s default relative-PATH refusal is conservative. |

The C gate’s exact `sandbox_check == 1` delegate queries should stay: restoring Rust’s acceptance of *any* failed lookup would again confuse service absence with policy denial.

For **D, profile agreement and libinfo**:

The drift test correctly captures the present intended difference: **two additional Mach denies and two resolver-socket denies**. Every C restriction is represented in `game.sb`; rule order is preserved for the common rules. This is useful drift detection, not independent validation of their security properties.

The resolver-socket rules are redundant under the current blanket network deny but useful explicit documentation. The two additional Mach denies make bare C application weaker on those named services. If bare execution is intended to have the launcher’s delegate coverage, add those two names to the C policy and independent query list. Otherwise, state that difference plainly.

Dropping `opendirectoryd.libinfo` is a justified compatibility correction on the supplied evidence. It restores the authoritative home lookup while the demonstrated resolver path remains blocked. Apple’s published Libinfo implementation sends user queries through the directory-service channel and explicitly leaves host/address-info callbacks unsupported in that module. That supports the distinction between account lookup and the tested DNS path. It does **not** prove every possible directory-service request is harmless or incapable of causing remote work on a differently configured Mac. [Apple Libinfo implementation](https://raw.githubusercontent.com/apple-oss-distributions/Libinfo/main/lookup.subproj/ds_module.c).

Thus: no demonstrated DNS escape from this removal on this Mac, no regression from the archived Rust policy, but a real retained service capability within the acknowledged denylist design.

For **E, what the passing suite establishes**:

The raw connect/sendto tests, family-preserving IPv4-mapped probes, live loopback positive controls, child execution, forced system-resolver selection, and resolver re-allow control are useful evidence. The received-datagram test establishes that inherited control connections can deliver usable socket capabilities; it does not establish a safe broker or launcher exemption.

The launcher sabotage tests catch gross removal of network, socket-option and write restrictions. They do not authenticate policy or prove completeness. The drift comparison catches disagreement between two texts; coordinated weakening can still pass it.

Skipping Seatbelt tests when application is unavailable is reasonable for developer runs. Acceptance still requires an explicit outside-sandbox run with no skips, as supplied here.

For **F, fitness for the owner’s surface review**:

The main sequence and one-rule-per-line profile are readable. Keep the plain control flow and aggregated refusal items. No framework or additional abstraction is needed.

Make these small surface corrections:

- Separate trusted policy selection from repository discovery.
- Rename `NoInheritedSockets` to `NoOpenSockets`; it checks every socket present at that point.
- Make descriptor inspection distinguish “socket” from “cannot inspect” in diagnostics.
- Replace “the probes are what holds” with the precise statement that the applied kernel policy contains the process and probes check selected properties.
- Correct `d1netgate.c:239`, which still says successful application is required despite the implementation.
- Remove or clearly archive the obsolete live instructions in `containment/README.md:51,73–78,93–104`, including commands for the archived crate. The owner should not have to reconcile contradictory operating procedures.

For **G, the must-fix list before shipping piece 2 as the interim security launcher**:

1. Anchor the applied policy to the trusted launcher, independently of checkout markers and caller working directory.
2. Close the proof-only command-execution entry and restore fail-closed handling of unknown/failed C application; verify the chosen composition mechanism.
3. Establish the launcher’s pre-exec environment/stdio contract before accepting agent-controlled invocation environments.
4. Add the selective-allowance control, actual C integration controls, Mach checks, and independent write-exclusion fixtures; correct the masked listening test.
5. Check close-on-exec results and verify descriptors in the final exec’d command; repair refusal formatting and `SIGPIPE` handling.

The accepted interim Mach/exec denylist limits do not require expanding this piece into the broker or final allowlist design. The current provenance and admission gaps do require correction.