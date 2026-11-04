**Verdict: request changes.** Several reported inputs are closed, but sibling bypasses remain, and the installer introduces an unsandboxed protected-file truncation route.

Reviewed branch `mythos-audit-fixes` at `65cfb107d51284b9a99b86cd0861576899dfee01`, including `c389740..65cfb10`, the previous review, and the three requested policy documents. Findings below are static traces unless explicitly stated otherwise. Examples assume cwd `/Users/ryanheffernan/Documents/projects/d1preservation`.

**Findings**

1. **High — zsh clobber redirections bypass the companion’s new destination check.**

   Sources: [shell.go:545](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:545), [shell.go:555](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:555), [shell.go:50](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:50).

   Admitted input under zsh:

   ```sh
   node /Users/ryanheffernan/.claude/plugins/cache/openai-codex/codex/1.0.6/scripts/codex-companion.mjs status >!CLAUDE.md
   ```

   `scanShell` accepts this. `shellArguments` recognizes only `>` as the operator and treats `!CLAUDE.md` as its destination. That unprotected repository pathname passes `outputInRepository`. Zsh instead interprets `>!` as an operator and truncates `CLAUDE.md`.

   The installed `zshmisc(1)` documents this behavior. `>>!`, `>&!` and `&>!` have the same parsing mismatch. The companion route skips `Tripwire`, so spelling the protected filename directly does not rescue this case.

   **Smallest fix:** reject unsupported redirection operators, including the `!` forms, before accepting companion commands; alternatively prohibit companion output redirections.

2. **High — Bash arithmetic expansion hides command substitution from the shared grammar.**

   Sources: [shell.go:438](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:438), particularly the single-quote branch at [shell.go:444](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:444).

   Admitted input in an elevated Bash session:

   ```sh
   xcodebuild -version $['$(cp runs/p CLAUDE.m?)']
   ```

   `scanShell` does not recognize `$[...]`. It treats the single-quoted span as inert and therefore overlooks its `$(`. Bash processes this span inside arithmetic expansion and executes the substitution. A subsequent arithmetic syntax error does not undo the `cp`.

   `CLAUDE.m?` avoids the spelling-based tripwire. This uses an `xcodebuild` query, independently of the accepted project-build limitation. The companion parser shares the same vulnerability.

   **Verified behavior:** a harmless Bash invocation using only `printf` emitted the substitution marker before reporting the arithmetic error. No attack payload was executed.

   **Smallest fix:** reject `$[` outside genuine single-quoted shell text, and reject other expansion forms the scanner does not parse.

3. **High — admitted repository output paths remain replaceable after validation.**

   Sources: [shell.go:362](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:362), [shell.go:367](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:367), [shell.go:51](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:51).

   Concrete interleaving:

   - An admitted companion command has `status > runs/out.log`; the hook checks an ordinary, unprotected `runs/out.log`.
   - After that check, another sandboxed agent call replaces it:

     ```sh
     ln -sf "$PWD"/CLAUDE.m? runs/out.log
     ```

   - The unsandboxed companion shell then opens the replacement and truncates `CLAUDE.md`.

   The replacement command names no protected spelling and changes only the unprotected directory entry. `ProtectedTarget` resolves the destination at check time; it does not bind the shell’s later open to that object. Excluded-command output has the same problem.

   Removing `$TMPDIR` closes the original non-racing input, but moving logs into agent-writable `runs/` does not close this sibling.

   **Smallest fix:** prohibit those unsandboxed redirections, or open output through a trusted broker that enforces the destination restriction at use time.

4. **High — the new hard-link probe can truncate a protected file outside every sandbox.**

   Source: [install.sh:182](/Users/ryanheffernan/Documents/projects/d1remote/containment/install.sh:182), especially line 185.

   Pre-existing input, where `P` is the installer’s PID:

   ```text
   runs/.codex-link-source-P -> ../CLAUDE.md
   ```

   The installer executes:

   ```sh
   : > "$source_file"
   ```

   This runs directly in the owner’s terminal, follows the symlink and truncates `CLAUDE.md` before any Codex probe starts. An agent can prepare the predictable pathname while the earlier installer controls run.

   A pre-existing regular file at that name is also truncated. Line 187 unconditionally removes both the source and control-link names, including pre-existing entries when control-link creation failed.

   **Smallest fix:** create an exclusive, private probe directory; create source files without following existing links; remove only entries created by this invocation. Do not use PID-derived names directly in an agent-writable directory.

5. **High — updater source classification still misses case-variant source-tree names.**

   Sources: [update.sh:45](/Users/ryanheffernan/Documents/projects/d1remote/containment/update.sh:45), [update.sh:50](/Users/ryanheffernan/Documents/projects/d1remote/containment/update.sh:50), [update.sh:54](/Users/ryanheffernan/Documents/projects/d1remote/containment/update.sh:54).

   Concrete pre-existing layout on the case-insensitive volume, with the directory stored as `Go`:

   ```text
   containment/Go/hook/planted_test.go -> ../../../runs/payload.go
   ```

   `payload.go` declares package `hook` and an attacker-controlled `init`.

   `find` emits the stored `containment/Go/...` spelling. Both shell classifications require lowercase `containment/go/*`, so neither rejects the symlink nor adds it to `extra`. The case-sensitive Git object lookup does not find that spelling, and it is reported as “kept, never built.”

   Checkout restores tracked files without removing the untracked source. The installer’s lowercase `cd "$root/containment/go"` resolves to the existing `Go` directory and builds it. Installed Go source, `go/build/build.go:886–900`, confirms that symlinks to source files proceed to source matching; only symlinks to directories are skipped.

   This is a static checkout/build trace; I did not construct or execute this layout.

   **Smallest fix:** classify source-tree paths without case and fail closed on unexpected casing and symlinks. Building from the fresh private checkout avoids the mutable destination-tree issue more broadly.

6. **High — worktree protection remains incomplete across harnesses and layouts.**

   Sources: [install.go:34](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/install.go:34), [codex.go:73](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/codex.go:73), [protect.go:240](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/protect.go:240).

   The original command remains admitted in sandboxed **Claude Code**:

   ```sh
   cp runs/p runs/wt-demo/CLAUDE.m?
   ```

   Claude’s generated deny rules still cover only main-checkout paths. `worktreeTarget` protects explicit edit targets, while this Bash command avoids the tripwire. The revised documentation explicitly acknowledges the remaining opening at `agent-containment.md:180`.

   Codex also receives no corresponding protected-path rules for an existing worktree at, for example, `runs/review`:

   ```sh
   cp runs/p runs/review/CLAUDE.m?
   ```

   That layout matches none of the generated patterns, and `worktreeTarget` also excludes it. Enumerating four spellings of `wt-` does not cover arbitrary Git worktree locations.

   **Smallest fix:** provision equivalent protection for every permitted worktree in both harnesses before granting writes, and refuse unprovisioned layouts.

7. **Medium — test-option parsing still admits execution and introduces a compile-only false refusal.**

   Sources: [hook.go:365](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/hook.go:365), [hook.go:397](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/hook.go:397).

   Admitted Go input, for an agent-created ungated package:

   ```sh
   go test -o -c ./runs/ungated
   ```

   Go consumes `-c` as the **value of `-o`**, then executes the tests. `onlyBuilds` ignores option arity and instead sets compile-only mode. The installed Go flag parser confirms that value-taking flags consume the following argument.

   Other siblings include:

   ```sh
   go te''st ./runs/ungated
   cargo test --manifest-path runs/ungated-rust/Cargo.toml --test probe -- --no-run
   ```

   The first defeats subcommand recognition because internal shell quoting is not removed. In the second, `--no-run` goes to the test binary, while `onlyBuilds` counts it as a Cargo option. An ungated `harness = false` target can execute its own `main`; both forwarding and custom harnesses are documented in installed `cargo-test(1)`.

   The revision also newly refuses this compile-only input:

   ```sh
   go test -c -run -c=false ./runs/ungated
   ```

   Go consumes `-c=false` as the `-run` pattern and retains compile-only mode; the hook incorrectly changes it to false.

   **Smallest fix:** parse shell words, option arity and argument terminators before calculating effective compile-only mode.

8. **Medium — the hard-link probe can report success for a refusal at the wrong destination.**

   Sources: [install.sh:189](/Users/ryanheffernan/Documents/projects/d1remote/containment/install.sh:189), [install.sh:192](/Users/ryanheffernan/Documents/projects/d1remote/containment/install.sh:192).

   Pre-existing input:

   ```text
   runs/.codex-link-P -> ../containment/go
   ```

   `/bin/ln` follows a destination symlink to a directory unless instructed otherwise, as documented in installed `ln(1)`. The probe therefore attempts to create:

   ```text
   containment/go/CLAUDE.md
   ```

   An `Operation not permitted` refusal there is reported as successful protection against hard-linking `CLAUDE.md` into `runs/`. The intended operation was never tested.

   Consequently, an implementation that permits linking the protected source into ordinary writable space but denies creation inside the protected tree can pass this probe falsely. The successful-link/write-open branch fixes the original unconditional `OPEN` handling, but this negative branch remains unsound.

   **Smallest fix:** use a guaranteed-fresh destination in an exclusively created directory and distinguish setup failures from the operation being measured.

**Codex permissions assessment**

The generated absolute glob keys with `"read"` are supported configuration syntax. The permissions guide discusses read/write globs and identifies portability limitations on Linux, WSL and Windows; their existence is not itself a macOS configuration error. [Configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference), [Permissions](https://learn.chatgpt.com/docs/permissions).

The documented precedence is: more-specific entries override broader entries; equal-path ties prefer `deny`, then `write`, then `read`. That supports exact protected-path carveouts. However, the guide does **not define how glob specificity is calculated against a concrete workspace root**. It therefore does not, by itself, establish the particular assumption at `codex.go:75–83` that these wildcard rules win when the worktree becomes the workspace root. I found no documentation establishing the opposite either. Runtime enforcement remains unverified. [Permissions](https://learn.chatgpt.com/docs/permissions).

The managed default and profile allowlist structure is documented, including denial of omitted profiles on supporting clients. [Managed configuration](https://learn.chatgpt.com/docs/enterprise/managed-configuration).

**Disposition of the nine claimed fixes**

“Verified” below means the reported input is closed by the inspected source, not that runtime enforcement was exercised.

| Previous finding | Disposition |
|---|---|
| **1 — companion redirection** | **Not verified as complete.** Ordinary `>` is checked; zsh clobber operators and destination replacement remain, findings 1 and 3 above. |
| **2 — `$TMPDIR` symlink** | **Not verified as complete.** The unchecked exception is removed; admitted repository output remains raceable, finding 3. |
| **3 — excluded shell grammar** | **Not verified as complete.** The reported `=(...)` input is refused; `$[...]` remains executable, finding 2. |
| **5 — worktree copies** | **Not verified.** Codex patterns were added, but Claude’s original opening remains, other layouts are omitted, and matching-glob enforcement was not exercised. |
| **6 — updater symlink source** | **Not verified as complete.** The lowercase example is caught. Non-directory enumeration also includes FIFOs and sockets, but case-sensitive classification leaves finding 5. |
| **7 — repeated Go Boolean flags** | **Not verified as complete.** The exact repeated-flag input is refused; option values, quoting and Cargo argument boundaries remain mishandled, finding 7. |
| **8 — hard-link probe** | **Not verified as complete.** A successfully created writable alias now fails installation; a refusal at a redirected destination can still pass, finding 8. |
| **9 — dangling-symlink cleanup** | **Verified for the reported input.** `-L` preserves the pre-existing `.cargo/config.toml` entry. The newly added hard-link setup has a separate pre-existing-entry defect, finding 4. |
| **10 — `tee` operand false refusal** | **Verified.** `grep -n tee CLAUDE.md` reaches the reader check without treating its operand as a command; command-position `tee` remains refused. |

**Limits of verification**

- `/etc/codex/requirements.toml` is absent here. I did not launch Codex or measure its generated Seatbelt policy.
- No attack payload, repository tests, launcher, updater or installer was executed. The only shell-behavior experiment used `printf` to confirm arithmetic substitution.
- Glob/workspace precedence, stored-case matching, missing-path protection, ancestor renames, hard-link enforcement and plugin profile selection remain unmeasured.
- The accepted `xcodebuild` project-build limitation is omitted.
- The checkout remained clean. The initial system Git shim’s attempted Xcode-cache write was denied; subsequent Git reads used the direct binary with optional locks disabled.


Codex session ID: 01a1a43e-d5cc-7a71-84f2-fd3934782e84
Resume in Codex: codex resume 01a1a43e-d5cc-7a71-84f2-fd3934782e84
