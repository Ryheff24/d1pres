# C boot-gate review — 2026-10-16

**Verdict: not yet.** The profile transplant is faithful, and the three main-entry calls are present. However, the inherited-socket exception admits an arbitrary relay, refusal diagnostics can themselves use a forbidden socket, and several probes can report success without establishing their claimed restriction.

This was a read-only review. No files were changed and no game or live sandbox probes were run. The supplied measurements are accepted.

Below, `d1netgate.c` means `containment/c/d1netgate.c`.

## A. Soundness of the profile

### A1. High — The broker exception currently admits an arbitrary relay

**Location:** `d1netgate.c:244–245,269–273`.

**What breaks:** Setting `D1_NETGUARD_FD` exempts any inherited `AF_UNIX` socket. Its peer could forward network requests, write protected files, or pass a connected INET socket after the scan. The game then has precisely the capabilities the gate is supposed to exclude.

**Evidence:** The check establishes only descriptor number and address family. It does not establish an unnamed, connected socketpair or a trusted broker. The supplied measurements establish that inherited Unix connections and subsequent `SCM_RIGHTS` transfers work. Moreover, `atoi("")`, `atoi("garbage")`, and `atoi("0junk")` all select fd 0.

**Smallest fix:** Remove the exception while no Go broker exists. When it returns, require strict numeric parsing, a designated fd above stdio, and the expected connected, unnamed socket type. Those checks establish shape; the trusted launcher must establish the peer. An environment variable cannot authenticate it.

Preservation of an existing connection is a **known Seatbelt limitation**. Exempting an unauthenticated connection is a **mistake here**.

### A2. High, acknowledged design limit — Named denies do not contain arbitrary delegated work

**Location:** `d1netgate.c:55–70,284`; main calls at `d1-recomp/src/main.rs:161`, `d1-oracle/src/main.rs:2094`, `d1-replay/src/main.rs:414`.

**What breaks:** Unlisted Mach services remain allowed. For example, `com.apple.SystemConfiguration.configd` is absent despite the recorded successful lookup under `deny network*`; `game.sb:29` explicitly names it. The OpenDirectory services named in `game.sb:16–17` are also absent. Reaching an unlisted service is not itself proof of a usable network relay, but this policy supplies no general barrier against one.

The two exec literals restrict paths, not equivalent functionality: a copied executable or another implementation can execute. Such a child still inherits the sandbox, so copying `open` is **not by itself** a demonstrated network escape.

Existing Mach send rights are another gap: denying lookup does not revoke a previously acquired right, and `/dev/fd` does not enumerate Mach ports. Calling the gate first in `main` still follows dynamic-library initializers. Chromium explicitly designs around initializers acquiring files and Mach ports before `main`. [Chromium’s Seatbelt design](https://raw.githubusercontent.com/chromium/chromium/main/sandbox/mac/seatbelt_sandbox_design.md).

**Smallest fix:** Preserve the documented distinction between this interim restriction set and complete containment. The complete fix belongs to the Go launcher: apply before executing the game, control inherited capabilities, and replace the Mach blacklist with an experimentally justified allowlist. Wholesale exec restriction also needs the documented link/run split.

These are **known limitations of the chosen policy and application timing**, not losses introduced by the C translation. Adding one more service name does not close the class.

### A3. Medium — Broad temporary-directory access makes protection depend on installation location

**Location:** `d1netgate.c:71–75`.

**What breaks:** The profile permits writes throughout `/private/tmp` and `/private/var/folders`, including unrelated same-user inputs and caches wherever filesystem permissions allow. A checkout under `/private/tmp/work/repo`, for example, would have writable procedure Markdown and source files. `D1_REPO` does not subtract the repository from those broader permissions.

**Evidence:** The only final exclusions are the `.sb` suffix and `/private/tmp/claude` prefix. Ordinary repository documents match neither. The missing repository probes in B2 let this case pass.

**Smallest fix:** For the interim, reject repository placement inside either broad writable temporary tree. Alternatively, explicitly protect the repository while allowing `runs/`, including protection against renaming writable ancestors. The recorded parent-rename behavior means a deny on the repository alone is insufficient in that layout. Ultimately, use launcher-owned scratch space instead of whole shared temporary trees.

For the current checkout under `/Users/.../Documents`, the default write deny protects procedure documents, shell startup files, and LaunchAgents. Missing individual shell filenames from the probe list does not make them writable.

**Regex/subpath assessment:** The C escaping produces the intended `\.sb$` expression; the Claude prefix covers its root and descendants. `subpath` denotes a directory tree, not an arbitrary textual prefix. The supplied evidence does not establish a case-alias or hard-link bypass; those require controls rather than an asserted vulnerability. These remain pathname rules, not a general guarantee that every future input to another process is immutable.

## B. Soundness of the probes

### B1. High — Refusal can transmit through the socket being refused

**Location:** `d1netgate.c:83–86,277,288–303`.

**What breaks:** Give the process a connected INET socket as fd 2. The inherited-descriptor check detects it, then `netgate_fail()` writes the refusal message through that same socket. The process exits 2 only after transmitting.

**Evidence:** `fprintf(stderr, ...)` is immediate, and the supplied measurements establish that a preconnected INET socket continues working after applying the profile. Earlier failures also print before descriptor validation.

Separately, a failed `sandbox_init` still proceeds through all network and delegate probes. An apply failure can therefore cause socket attempts under a profile already known to be unsuitable.

**Smallest fix:** Establish a safe diagnostic destination before any diagnostic write. If stderr is a prohibited socket, refuse silently with `_exit(2)`. Stop immediately when profile application fails; do not continue probing. Moving the descriptor scan earlier without changing its logging is insufficient.

### B2. Medium — Repository probes were lost, and `asked` does not establish coverage

**Location:** `d1netgate.c:213–240`; comparison: `archive/d1-netgate-rust/src/lib.rs:792–800`.

**What breaks:** The C port dropped checks for:

- `D1_REPO "/CLAUDE.md"`
- `D1_REPO "/d1-server/crates/d1-recomp/src/main.rs"`

It added `.zprofile`, but that does not replace repository coverage.

**Evidence:** The home directory normally increments `asked` immediately. Consequently, missing shell files and a missing harness directory do not prevent success. Removing the Claude regex can go undetected when `/private/tmp/claude-<uid>` is absent. No probe tests the `.sb` exclusion inside an otherwise writable tree.

The `/private/tmp` positive control correctly rejects a query that always says “denied.” It does not establish that each negative path exists or that either regex works. `lstat` also accepts a dangling symlink, whose missing target can recreate the documented nonexistent-path false pass.

Finally, querying `file-write-data` does not independently test creation, unlinking, renaming, or metadata modification covered by `file-write*`.

**Smallest fix:** Restore both repository checks. Treat unexpected `stat` errors and truncation as failures; distinguish absent optional paths from successfully tested restrictions. Add parent-created disposable fixtures in the Go tests for the Claude and `.sb` exclusions, including create/rename/unlink attempts. Keep independent checks that the required rules exist when runtime fixtures do not.

Do not describe `asked > 0` as proof of all write protections.

### B3. Medium — The profile parser can silently reduce the proof

**Location:** `d1netgate.c:149–175,182–199`.

**What breaks:** Editing the policy can simultaneously remove the expectation that would detect its weakening.

**Evidence:**

- Removing one service or executable from the macro removes its probe.
- `strstr(p, "))")` is not balanced-list parsing. Nested filters can terminate the selected clause early.
- Multiple deny clauses are not all visited.
- `strchr(p, '"')` is not bounded by `end` and does not understand escaped quotes.
- Finding a clause does not require finding any recognized entries.
- Long entries are silently truncated before being checked.

The current simple macro has 12 service names and two exec literals, and this parser finds them correctly. The defect is silent acceptance of future changes, not an observed misparse of today’s text.

**Smallest fix:** Replace profile parsing with short, explicit probe arrays and a Go consistency test. Independent expectations are useful here. Do not spend the C budget implementing a Scheme parser.

### B4. Medium — An absent service counts as a denied service

**Location:** `d1netgate.c:168–173`.

**What breaks:** A service absent from the current bootstrap namespace passes even if the sandbox would allow it. So do other lookup failures.

**Evidence:** Every result except `KERN_SUCCESS` is accepted. Apple distinguishes permission denial, unknown service, resource failures, and other Mach errors. [Apple’s bootstrap implementation](https://raw.githubusercontent.com/apple-oss-distributions/launchd/main/liblaunch/libbootstrap.c).

**Smallest fix:** Require an exact denial from `sandbox_check(getpid(), "mach-lookup", SANDBOX_FILTER_GLOBAL_NAME, name)`, treating errors as failures. The global-name filter is 2 in WebKit’s maintained SPI declaration. Retain actual lookup as a supplemental check if useful, but do not equate absence with policy denial. [WebKit’s sandbox SPI](https://raw.githubusercontent.com/WebKit/WebKit/main/Source/WTF/wtf/spi/darwin/SandboxSPI.h).

### B5. Medium — Descriptor enumeration has fail-open error paths

**Location:** `d1netgate.c:248–269`.

**What breaks:** A partial directory read can be mistaken for a complete scan. An uninspectable descriptor can be silently ignored.

**Evidence:** `readdir()` returning NULL is accepted without checking `errno`; every `fstat()` error is skipped. The latter also hides the expected stale entry for the enumeration directory, which the code closes before inspecting its saved list.

**Smallest fix:** Inspect entries while the directory remains open, skip `dirfd(d)` explicitly, distinguish EOF from `readdir` failure, and fail on unexplained inspection errors. Require the scan to run without concurrent descriptor changes.

Using `/dev/fd` rather than the current descriptor limit is correct. The 4,096-entry cap refuses safely, but creates an avoidable false refusal and unnecessary storage.

### B6. Probe boundaries and false refusals

**Locations:** `d1netgate.c:90–143,180–210,240`.

- **Correct:** `process-exec*`, `job-creation`, and write queries require exactly the documented result. `-1` is not accepted as denial.
- **Correct:** `ECONNREFUSED`, `EINPROGRESS`, and successful UDP sends fail the network check. An absent port-9 listener cannot masquerade as sandbox denial.
- **Limited coverage:** TCP/UDP loopback and TCP own-address tests do not prove all destinations, protocols, inbound operations, or Unix connections are denied. A remote-only allowance could pass these samples.
- **Limited coverage:** Denial of `SO_REUSEADDR` does not establish denial of every IP-level option. A selectively weakened option rule could pass. Pin the blanket clause and test harmless IPv4/IPv6 option controls; do not attempt a multicast join as a probe.
- **No-carrier interfaces:** `IFF_UP` does not mean carrier is present. However, lack of carrier alone is not a demonstrated bug here: XNU calls the MAC connect check before entering the protocol connection path. Do not “fix” this by accepting `ENETUNREACH` as denial. Add an inactive-interface regression case and include the actual address in diagnostics. [XNU connect implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/uipc_syscalls.c).
- **Expected conservative refusals:** Resource exhaustion, interface-list failure, or unsupported socket families can refuse a correctly restricted process. These are inability to prove, not evidence that networking is permitted.
- **Future compatibility:** Requiring `/private/tmp` to be writable rejects a stricter correct profile. That is consistent with today’s exact profile, but must change when the launcher narrows scratch access.

The successful application of the reviewed blanket rules remains essential. These probes are samples, not a substitute for reviewing those rules.

## C. Robustness as C

### C1. Medium — Repository paths cross two quoting languages, inconsistently

**Location:** all three `build.rs:14–18`; `d1-recomp/src/fntest.rs:540–565`; `d1netgate.c:73`.

**What breaks:** The build scripts wrap the repository path in C quotes without escaping it. `fntest.rs` escapes C quotes and backslashes, but the resulting string is then inserted unescaped into an SBPL string.

| Path content | Result |
|---|---|
| Spaces | Fine: these are argument-vector calls, not shell command strings. |
| `"` | Build-script C literal can break; fntest can produce malformed or altered SBPL. |
| `\` | Build scripts can interpret C escapes or alter the path; fntest preserves bytes that still need SBPL handling. |
| Valid non-ASCII UTF-8 | No inherent problem with ordinary characters. |
| Non-UTF-8 bytes | `display()` / `to_string_lossy()` can select a different pathname. |
| Newlines/control characters | Not safely represented by the current construction. |

**Smallest fix:** Explicitly reject unsupported metacharacters and non-UTF-8 paths in both build routes, while retaining spaces and ordinary Unicode. Supporting arbitrary paths requires correct C encoding plus SBPL parameterization or escaping. Use one consistent rule for standalone and runtime compilation so their profiles remain identical.

Also fail canonicalization explicitly; `unwrap_or(repo)` hides the loss of the canonical-path assumption.

### C2. Low — Check truncation and socket setup errors

**Location:** `d1netgate.c:97–100,165–166,190–191,219–224`.

**What breaks:** Unchecked `snprintf` truncation can query a different existing pathname. Ignored `fcntl` failures can leave a supposedly nonblocking probe blocking, especially under an ineffective profile.

**Smallest fix:** Reject truncated policy names and paths; check both `F_GETFL` and `F_SETFL`. Diagnostic-only truncation is less serious.

Current fixed service names and executable paths fit their buffers. The socket address copies fit `sockaddr_storage`. Saving `errno` before `close()` is correct.

### C3. Startup-only behavior is acceptable, but must be explicit

**Location:** `d1netgate.c:80–86,253,281–305`; `d1run.c:613–614`.

Sequential successful calls work: the failure counter remains zero, and identical profiles stack under the supplied measurements. Do not add a “passed once” shortcut that skips the second proof.

The function is neither thread-safe nor async-signal-safe: global diagnostic state, static descriptor storage, stdio, and library lookups preclude that. The inspected calls are ordinary startup calls, so this is a contract to document, not a reason to implement signal-handler machinery.

The second descriptor scan checks everything open **then**, including sockets created after `main`; “inherited” is therefore an imprecise name. Concurrent descriptor creation or an intentional internal socketpair can invalidate that assumption.

Diagnostics can also block before `_exit(2)`, and a caller’s SIGPIPE disposition can affect the exit status. The refusal path should use a validated destination and best-effort output.

## D. Fitness for the owner’s review

**Location:** `d1netgate.c:1–306`.

The file is **306 physical lines, 289 nonblank lines, and 246 lines excluding blank lines and `//` comments**. It exceeds the owner’s approximately 250-line file budget; counting comments away does not reduce what the owner must review.

The socket helpers and top-level sequence are readable. The least reviewable parts are the ad hoc clause parser, accumulated-error machinery, and descriptor snapshot.

The smallest useful reduction is:

- Replace clause parsing with explicit expectations checked by Go tests.
- Make fatal failure immediate, using safe diagnostics.
- Stream the descriptor scan instead of retaining 4,096 entries.
- Shorten the historical introduction; retain operational assumptions and reasons for unusual API choices.
- Rename `netgate_open` to `failure_count` if aggregation remains, and `netgate_inherited` to `netgate_check_fds`.

Do not achieve the budget through compressed statements or removing necessary checks.

Profile application, policy parameters, scratch-directory creation, environment/descriptor hygiene, and broker authentication belong in the future Go launcher. C should retain the small proof and refusal path.

## E. Drift risks

### E1. Medium — The two profiles already differ in security-relevant ways

**Location:** `d1netgate.c:54–75`; `containment/go/profiles/game.sb:1–30`.

| Property | Interim C profile | `game.sb` |
|---|---|---|
| New network connections | Blanket deny | Allows outbound to `BROKER_SOCKET` |
| Socket options | Blanket deny | No explicit denial |
| Mach lookup | Twelve-name blacklist | Wholesale deny |
| Exec | Two denied paths | Wholesale deny with `GATE`/`GAME` exceptions |
| Job creation | Explicit deny | No explicit rule |
| Filesystem writes | Allowlist and final exclusions | Default allow |

The Mach and exec differences reflect the target design. Missing write and socket-option protections are regressions relative to the interim requirements. Absence of the job rule is a textual difference; it does not override the recorded observation that launchd submission already fails under any sandbox.

The broker-path allowance contradicts `netguard-requirements.md:204–206`, which explicitly replaces it with an inherited control descriptor.

A byte comparison cannot currently assert that these profiles are equivalent. The C macro does reproduce the archived game-profile construction byte-for-byte at the same repository root.

### E2. Smallest useful drift tests

**Location:** `containment/go/harness_test.go:18–69`; `d1netgate.c:54–75,281–305`.

A standard-library Go test can invoke `clang` through `os/exec`; that needs no cgo:

1. Compile a tiny helper that includes this C file and prints `D1_NETGATE_PROFILE` with a fixed test repository path. Compare against reviewed expected policy tokens, preserving rule order.
2. Check both profiles against explicit shared requirements, with a short list of intentional differences. Reject the obsolete broker-path exception and missing shared protections.
3. Compile a separate test helper that applies deliberately weakened profiles and calls the C probe functions. Do not call `d1_netgate()` for these controls—it would reinstall the correct profile and conceal the weakening.
4. Exercise missing individual clauses, absent delegates, regex fixtures, repository writes, descriptor errors, malformed fd variables, socket stderr, and repeated application. Keep this mechanism out of production environment variables.
5. Restore a small source-level call-site check for the three mains and `d1run_start`; label it drift detection, not enforcement.

Runtime tests must distinguish “could not apply the test profile” from “the negative control was caught.” The supplied `--help` results establish basic startup behavior, not these sabotage cases.

## F. Verdict and must-fix list

**Do not ship this revision as the interim gate yet.**

Must fix:

1. Remove the unauthenticated `D1_NETGUARD_FD` exception until the broker exists.
2. Prevent diagnostics from using prohibited inherited sockets; stop immediately on apply failure.
3. Make descriptor enumeration and inspection errors fail closed.
4. Restore repository write coverage; stop treating optional-path absence and arbitrary lookup failure as proof.
5. Replace the fragile profile parser with independently checked expectations.
6. Make repository-path encoding consistent and explicit.
7. Add profile/probe drift controls, reconcile the shared protections in `game.sb`, and bring the C file within the owner’s review budget.

The interim gate can then serve its documented, limited role. Complete containment of a hostile agent-run binary still requires the Go launcher and the stronger capability restrictions already identified in the design.