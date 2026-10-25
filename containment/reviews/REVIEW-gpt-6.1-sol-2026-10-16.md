**No—do not copy the procedure as written.** The changes improve direct socket containment, but they do not meet the stated boundary against agent-written native code or an agent routing around controls. The launchers leave their trust anchor writable, the hook admits a path race, and neither profile prevents several indirect network paths. Copy a revised procedure only after the external launch controls are hardened, installed, and checked in both agent harnesses.

**Findings, ranked**

1. **High — An admitted command can replace the trust anchor.**  
   [hook.rs:75](/Users/ryanheffernan/Documents/projects/d1preservation/d1-server/crates/d1-netgate/src/hook.rs:75), [README.md:125](/Users/ryanheffernan/Documents/projects/d1preservation/archive/agent-hooks-rust/README.md:125).  
   An agent writes an unprotected helper, then runs it through an admitted launcher alias. The launcher’s profile gives it the user’s file access, including `.claude/hooks/` and settings. It replaces a launcher or disables the hook; the next command runs unrestricted. The agent sandbox’s `denyWrite` does not accompany this command.  
   **Fix:** enforce protected-file and ancestor-directory write denials inside both launcher profiles, or put the complete launch policy and binaries behind a separate OS identity. User-owned copies protected only by the agent sandbox are insufficient.

2. **High — Canonicalized launcher aliases permit an execution race.**  
   [hook.rs:73](/Users/ryanheffernan/Documents/projects/d1preservation/d1-server/crates/d1-netgate/src/hook.rs:73).  
   `/tmp/l` points to the trusted launcher when the hook canonicalizes it. A background agent process changes that symlink before Bash executes `/tmp/l`. The replacement executes outside either gate. Aliases are expressly admitted and tested at lines 192–207.  
   **Fix:** require the exact pinned launcher pathname, reject writable aliases and path components, and protect its complete directory ancestry. Where supported, execute the verified open executable rather than resolving its name again.

3. **High — Game file writes can recruit a later unsandboxed process.**  
   [d1hle.c:637](/Users/ryanheffernan/Documents/projects/d1preservation/d1-server/crates/d1-recomp/runtime/d1hle.c:637).  
   `map_path` concatenates guest paths without rejecting `..` or following symlinks safely. With the default root, `/data/../../../Users/ryanheffernan/.zshenv` reaches the owner’s shell startup file. Guest open/write calls can plant a command that a later unsandboxed shell executes, reaching the network despite both gates passing. Native HLE code has still broader access.  
   **Fix:** give the game an OS-enforced, narrow writable directory; resolve guest paths beneath mount directory descriptors without traversal or symlink escape. Exclude shell configuration, launch agents, agent configuration, and executable inputs.

4. **High — `NESTED` accepts an unknown policy from inadequate samples.**  
   [lib.rs:327](/Users/ryanheffernan/Documents/projects/d1preservation/d1-server/crates/d1-netgate/src/lib.rs:327), [lib.rs:555](/Users/ryanheffernan/Documents/projects/d1preservation/d1-server/crates/d1-netgate/src/lib.rs:555), [d1netgate.c:166](/Users/ryanheffernan/Documents/projects/d1preservation/containment/c/d1netgate.c:166).  
   An enclosing sandbox can deny the four local-only probe destinations/ports while permitting other outbound traffic. After the nesting refusal, `check_local_only(false)` passes and skips descriptor/delegate checks. Likewise, a policy denying localhost, named delegates and the checked execs can pass the game probes while admitting off-machine connections. English EPERM text establishes neither policy identity nor completeness. The C gate additionally falls through on **any** apply failure with a null error buffer.  
   **Fix:** require successful application of the intended profile. Any composition exception must depend on an owner-controlled enclosing launcher, not sampled denial. Reject unidentified C apply failures.

5. **High — Arbitrary localhost access includes network relays.**  
   [lib.rs:101](/Users/ryanheffernan/Documents/projects/d1preservation/d1-server/crates/d1-netgate/src/lib.rs:101).  
   With an HTTP/SOCKS proxy or SSH forward listening locally, wrapped code connects to that endpoint and requests an external connection. Every startup probe still passes; another process performs the egress. The documented agent sandbox’s egress proxy presents the same problem when arbitrary code is allowed there.  
   **Fix:** separate agent research access from code execution. Restrict code to explicitly trusted local endpoints and exclude proxy/forwarding services; otherwise use an isolated environment without access to host relays.

6. **High — The measured multicast escape remains available to native code and children.**  
   [lib.rs:72](/Users/ryanheffernan/Documents/projects/d1preservation/d1-server/crates/d1-netgate/src/lib.rs:72), [d1net.c:288](/Users/ryanheffernan/Documents/projects/d1preservation/d1-server/crates/d1-recomp/runtime/d1net.c:288).  
   After either gate passes, an HLE, helper or child creates a UDP socket and calls `setsockopt(IP_ADD_MEMBERSHIP)`. The documented measurement says this emits an IGMP report despite `deny network*`. Fixing the guest’s `sceNetSetsockopt` dispatcher does not constrain arbitrary native code.  
   **Fix:** use an owner-controlled OS boundary demonstrated to block these emissions, including native socket options—potentially an isolated VM. Source audits alone cannot enforce this against deliberately written native code.

7. **High — Accepted inherited Unix sockets are unrestricted delegation channels.**  
   [lib.rs:498](/Users/ryanheffernan/Documents/projects/d1preservation/d1-server/crates/d1-netgate/src/lib.rs:498), [d1netgate.c:143](/Users/ryanheffernan/Documents/projects/d1preservation/containment/c/d1netgate.c:143).  
   A preconnected AF_UNIX socket to an unsandboxed relay at fd 0–2, or the environment-selected control fd, passes both checks. The game can write to it through the raw-descriptor HLEs; the peer performs network work. Neither check requires the control socket to be unnamed, as the requirements specify, nor establishes its peer’s provenance.  
   **Fix:** reject socket stdio and construct descriptor inheritance in the trusted launcher. Permit only the launcher-created channel to the constrained broker. Also account for inherited FIFOs and other writable IPC handles, which this scan ignores.

8. **High — The call-site scan cannot enforce comprehensive game gating.**  
   [callsites.rs:89](/Users/ryanheffernan/Documents/projects/d1preservation/d1-server/crates/d1-netgate/tests/callsites.rs:89), [callsites.rs:106](/Users/ryanheffernan/Documents/projects/d1preservation/d1-server/crates/d1-netgate/tests/callsites.rs:106).  
   A raw string containing a decoy `fn main` and expected gate line fools `first_statement`; the effective main can do something else. Extra binaries in an already-listed crate are not checked individually. Custom target paths, crates outside the parsed membership format, `build.rs`, proc macros and pre-main initializers also escape effective ordering checks. Build scripts execute **before** this test. Existing oracle integration tests execute game codecs without the game gate; `GAME_UNDER_LOCAL` deliberately gives the activity-host process network permission.  
   **Fix:** make an immutable external game launcher mandatory, including for game-running tests and codec workers. Separate codecs into a no-network process. Cargo metadata and syntax-aware target checks can improve drift detection, but cannot establish a hostile-code boundary.

9. **Medium — `require_loopback` protects the listed CLIs, not arbitrary wrapped programs.**  
   [lib.rs:102](/Users/ryanheffernan/Documents/projects/d1preservation/d1-server/crates/d1-netgate/src/lib.rs:102), [d1-localonly.rs:29](/Users/ryanheffernan/Documents/projects/d1preservation/d1-server/crates/d1-netgate/src/bin/d1-localonly.rs:29).  
   An admitted test/helper binds `0.0.0.0` without calling `require_loopback`. The measured profile admits that bind and LAN inbound traffic because its inbound condition tests the **local** address. The four CLI checks do not cover arbitrary commands or library entry points.  
   **Fix:** enforce peer locality in the profile, or restrict execution to reviewed listeners with enforced binds. Verify any inbound-rule replacement against a peer on a Mac-only virtual network, covering TCP and UDP.

10. **Medium — The standing procedure instructs agents to bypass the intended external anchor.**  
    [agent-containment.md:65](/Users/ryanheffernan/Documents/projects/d1preservation/containment/agent-containment.md:65), [agent-containment.md:75](/Users/ryanheffernan/Documents/projects/d1preservation/containment/agent-containment.md:75).  
    Point 1 and `autoMode.environment` say to run mutable game binaries bare; the run-form paragraph still names `target/release` as the admitted executable. An agent following that text outside the sandbox can execute a rebuilt binary before any effective gate. This conflicts with the README’s mandatory `d1-nonet` wrapper and its measured identical-profile stacking. Codex has no corresponding installed enforcement.  
    **Fix:** prescribe only the pinned external launcher; remove all bare-run instructions. Cover both gates’ refusals, game-running tests, and Codex explicitly. Require a completed, verified installation—the `denyWrite` example remains a placeholder.

11. **Low — The two hook rules reject their own documented launch command.**  
    [hook.rs:154](/Users/ryanheffernan/Documents/projects/d1preservation/d1-server/crates/d1-netgate/src/hook.rs:154).  
    With owner override unset, every documented absolute `.claude/hooks/d1-nonet …` command matches the `.claude` marker and fails `reader()`. `sandbox-off` allows it, but `protect` denies it. A marker-free alias passes instead, encouraging the weaker path identified above.  
    **Fix:** test complete events through both rules together. Make the write boundary an OS control and admit only the exact immutable launcher spelling.

12. **Low — The previously flagged named broker exception remains.**  
    [game.sb:7](/Users/ryanheffernan/Documents/projects/d1preservation/containment/go/profiles/game.sb:7).  
    The future game profile still allows new connections to `BROKER_SOCKET`; its tests require them. If that pathname is rebound to an unsandboxed relay, the game can delegate through it. The composition requirements explicitly replace this path with a preconnected descriptor. This earlier finding is not fixed in the reviewed piece.  
    **Fix:** remove the pathname permission and update the tests before accepting or integrating this profile.

**What should be kept**

- Gate calls precede application work in the listed binaries; the tokio servers gate before runtime creation.
- The four server CLI bind checks are wired before their listeners.
- Exact EPERM/EACCES handling, rejection of `sandbox_check` errors, Rust malformed-profile rejection, and inherited-INET detection are present.
- The guest IP socket-option refusal and the sabotage/positive controls are useful. Keep them as defense in depth.

**Limits and unverified behavior**

I read the collection’s listed material and the three earlier reviews, and searched workspace source for additional listeners and game execution. The pending GPT review file was absent. I changed nothing and ran no builds, tests, probes, or network operations; I did not read the excluded directories or derived binaries.

I relied on the supplied Seatbelt measurements. Unlisted Mach services remain allowed—including `configd`, already documented as reachable—and I did not establish which expose usable network actions. Before certification, probe inherited Mach send rights against a harmless local test service, descriptor scanning after lowering `RLIMIT_NOFILE`, and the C null-error path through fault injection. Netguard’s separate launcher WIP, dependencies, and full runtime/emulator memory safety were outside this review.