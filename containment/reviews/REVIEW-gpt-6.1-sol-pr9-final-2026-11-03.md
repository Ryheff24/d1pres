**Verdict: request changes.** The targeted fixes improve the hook, but protected-file writes and execution outside the required launcher remain admissible.

Reviewed local `main...HEAD`, ending at `92ba228`, with particular attention to `79418b3`, `db3ec47`, and `92ba228`. Findings below are source-level traces, supported where noted by installed manuals or official documentation. **No attack commands, tests, launchers, or installation were executed.** Command examples assume cwd `/Users/ryanheffernan/Documents/projects/d1preservation`.

**Findings**

1. **High — the companion route bypasses protected-output checks, including with the sandbox off.**

   Files: [hook.go:309](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/hook.go:309), [shell.go:29](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:29).

   Admitted command:

   ```sh
   node /Users/ryanheffernan/.claude/plugins/cache/openai-codex/codex/1.0.6/scripts/codex-companion.mjs status > CLAUDE.md
   ```

   `CompanionForm` accepts the script, subcommand, and redirection. `decideInRepository` immediately returns its result, bypassing `Tripwire`, `redirectsInRepository`, and `decideSandboxOff`. This also admits a Bash event carrying `dangerouslyDisableSandbox: true`, regardless of model.

   If that sandbox-off call executes, the shell truncates `CLAUDE.md` before Node starts. Codex’s managed profile cannot protect a redirection performed by its unsandboxed parent shell.

   **Smallest fix:** prohibit output redirections on companion commands, or apply the same protected-output checks before returning. Do not exempt this route from the sandbox-off decision.

2. **High — the `$TMPDIR` exception allows an existing symlink to redirect excluded-command output into a protected file.**

   File: [shell.go:322](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:322), particularly line 332.

   Concrete sequence, with an unused temporary pathname:

   ```sh
   ln -s /Users/ryanheffernan/Documents/projects/d1preservation/CLAUDE.m? "$TMPDIR/d1-review.log"
   ```

   ```sh
   xcodebuild -version > "$TMPDIR/d1-review.log"
   ```

   The first command spells no protected filename literally. For an elevated session, the second passes `ExcludedForm`: `inTemporaryDirectory` checks the **spelling** `$TMPDIR/NAME` and skips `ProtectedTarget` entirely. The unsandboxed shell follows the existing symlink when opening the output.

   This bypass requires no race.

   **Smallest fix:** remove the unchecked temporary-output exception. Resolve and validate the actual destination; reliable protection against replacement races requires sandboxed output opening or a trusted output broker.

3. **High — the excluded-command parser still accepts zsh execution syntax that `79418b3` rejects only in the tripwire reader.**

   Files: [shell.go:428](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:428), [protect.go:352](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/protect.go:352).

   Admitted in an elevated session:

   ```sh
   xcodebuild -version =(cp runs/p CLAUDE.m?)
   ```

   Under zsh, `=(...)` executes its contents and supplies a temporary filename. This behavior is documented in the installed `zshexpn(1)` manual.

   `scanShell` rejects `<(...)` and `>(...)`, but does not reject `=(...)` or an ordinary unquoted `(`. `Tripwire` then returns before invoking its stricter reader because `CLAUDE.m?` spells no protected name. Thus an admitted sandbox-off call executes the `cp` before `xcodebuild` processes its arguments.

   **Smallest fix:** apply a common restricted shell grammar to companion and excluded routes, rejecting unsupported quoting, parameter expansion, and process-substitution forms independently of whether a protected name appears.

4. **High — unrestricted excluded `xcodebuild` remains an arbitrary-code execution route.**

   Files: [shell.go:112](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:112), [agent-containment.md:339](/Users/ryanheffernan/Documents/projects/d1remote/containment/agent-containment.md:339).

   Admitted command:

   ```sh
   xcodebuild -project runs/payload.xcodeproj -target payload build
   ```

   An agent can create this unprotected project with a Run Script phase that writes a protected file or starts tests. `ExcludedForm` imposes no restrictions on `xcodebuild`’s project or build phases. Those scripts run outside the agent sandbox and receive no separate tool-hook decision.

   The documentation explicitly acknowledges this limitation. It nevertheless conflicts with the requested hostile-agent threat model and the broader claim that execution stays in the three prescribed places.

   **Smallest fix:** limit unsandboxed `xcodebuild` to query operations. Builds of agent-writable projects need an enforced containment boundary.

5. **High — `92ba228` does not extend path-based protection to worktree copies.**

   Files: [codex.go:57](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/codex.go:57), [protect.go:229](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/protect.go:229).

   Given an existing worktree and payload file:

   ```sh
   cp runs/p runs/wt-demo/CLAUDE.m?
   ```

   The hook admits this spelling. The generated requirements contain only `ProtectedPaths(config)` and `ProtectedTreePaths(config)` for the **main checkout**; they contain no corresponding worktree paths. The worktree’s instructions, containment sources, and gate call sites therefore retain workspace write access.

   `worktreeTarget` protects explicit Edit/Write/apply_patch targets, but it is not applied to arbitrary Bash writes. This leaves the worktree guarantee dependent on the same spelling-based tripwire that `92ba228` intends to supplement.

   **Smallest fix:** keep worktree locations read-only until trusted provisioning installs equivalent protections, or generate and enforce protected paths for every permitted worktree before granting write access.

6. **High — `update.sh`’s clean-source check overlooks untracked symlinked Go source.**

   Files: [update.sh:45](/Users/ryanheffernan/Documents/projects/d1remote/containment/update.sh:45), [update.sh:63](/Users/ryanheffernan/Documents/projects/d1remote/containment/update.sh:63), [install.sh:30](/Users/ryanheffernan/Documents/projects/d1remote/containment/install.sh:30).

   Concrete pre-existing input:

   ```text
   containment/go/hook/planted_test.go -> ../../../runs/payload.go
   ```

   Here `runs/payload.go` contains package `hook` and an `init` function that writes a protected file.

   `find containment -type f` excludes the symlink. Checking out tracked files does not remove this untracked entry, and `git diff --quiet` does not report it. The subsequent owner-terminal `go test ./...` includes it.

   I checked the installed Go source: `go/build/build.go:890` skips symlinks to directories, while symlinked source files proceed to `matchFile` and are opened.

   **Smallest fix:** inspect symlinks as well as regular files and reject unexpected source entries. Building from the fresh, private checkout would also remove dependence on the mutable destination tree.

7. **Medium — test containment can be bypassed by overriding the compile-only flag.**

   File: [hook.go:365](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/hook.go:365).

   Admitted command:

   ```sh
   go test -c -c=false ./...
   ```

   The hook treats the presence of any exact `-c` argument as proof that execution is compile-only. Go processes these Boolean flags in order; the final `-c=false` enables execution. This is supported by the installed `cmd/go/internal/test/testflag.go` and `cmd/go/internal/cmdflag/flag.go`.

   Existing packages with functioning test gates retain that independent protection. A newly created ungated test package can execute through this route, so the hook does not enforce the claimed universal rule.

   **Smallest fix:** parse the effective Go options, including repeated flags and argument boundaries; reject conflicting compile-only settings.

8. **Medium — the hard-link probe does not establish containment and cannot fail installation.**

   File: [install.sh:155](/Users/ryanheffernan/Documents/projects/d1remote/containment/install.sh:155).

   Two concrete outcomes are mishandled:

   - If `ln` succeeds, the script prints `OPEN`, removes the link, and leaves `codex_failed` unchanged.
   - Any `ln` failure becomes `OK`, including an existing destination or a failure unrelated to sandbox enforcement.

   Additionally, successful link creation alone does not establish whether opening that alias for writing is permitted. The probe’s message asserts that consequence without measuring it.

   **Smallest fix:** use a positive hard-link control, retain and classify errors, check write-opening through any successful alias without truncating or writing bytes, and fail installation on a demonstrated writable alias.

9. **Medium — probe cleanup can delete a pre-existing dangling symlink.**

   File: [install.sh:142](/Users/ryanheffernan/Documents/projects/d1remote/containment/install.sh:142), cleanup at line 153.

   Concrete input:

   ```text
   .cargo/config.toml -> ../runs/not-created.toml
   ```

   If the target is absent, `[ -e "$path" ]` returns false despite the symlink already existing. After the probe, `rm -f "$path"` removes that pre-existing protected entry—even if the sandbox correctly refused the write.

   Thus the probes can damage an existing filesystem entry despite writing no file-content bytes.

   **Smallest fix:** account for symlinks with `-L`/`lstat`, and remove only entries positively identified as created by the probe.

10. **Low — a pure read searching for `tee` is still refused.**

    File: [protect.go:525](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/protect.go:525).

    Refused command:

    ```sh
    grep -n tee CLAUDE.md
    ```

    The reader checks every argument’s basename for `tee`, including search patterns and filenames. It does not distinguish an operand from a command.

    **Smallest fix:** detect `tee` in command position; let reader-specific option validation handle operands.

**Codex requirements assessment**

The generated TOML layout is consistent with the official documentation: top-level `default_permissions`, a Boolean `[allowed_permission_profiles]` table, and `[permissions.d1]` extending `:workspace`. Defining the parent does not require allowing users to select it. Managed allowlists are documented to take precedence over legacy sandbox selection on supporting clients. [Managed configuration](https://developers.openai.com/codex/enterprise/managed-configuration)

Absolute filesystem keys and `"read"` values are supported. More-specific paths override broader workspace grants, so the intended existing-file restriction is documented behavior. However, that does not establish alias, ancestor-rename, or nonexistent-path behavior in the requested binary. [Permissions](https://developers.openai.com/codex/permissions), [Configuration reference](https://developers.openai.com/codex/config-reference)

The probe’s `-P d1 --include-managed-config -C ...` invocation matches the documented sandbox command interface. [CLI reference](https://developers.openai.com/codex/cli/reference)

I could **not verify Codex 0.160 runtime enforcement**:

- `/etc/codex/requirements.toml` is absent on this host.
- Local package metadata identifies the application bundle as `0.166.0-alpha.5.1` and the npm package as `0.164.0`.
- No Codex process or sandbox probe was launched.

Accordingly, these remain unverified: protection of an absent absolute file; hard-link alias writes; ancestor-directory renames; symlink replacement races; direct `apply_patch` enforcement; plugin `sandbox: "workspace-write"` mapping; and attempts to redefine or select permissions through writable user/project configuration. I found no demonstrated config-based override and am not reporting one.

The installer probes explicitly select `d1`. They therefore do **not** test default-profile selection, legacy `-s` fallback, plugin requests, alternate profiles, worktrees, or parent renames. They also sample several paths rather than testing every protected file, and their `"Operation not permitted"` match does not identify which operation failed.

**What is sound in the inspected source**

| Change | Assessment |
|---|---|
| `79418b3` tripwire reader | The listed comment, dollar-quote, `${`, unquoted-parenthesis, and non-descriptor `>&WORD` cases now reach refusals when the tripwire runs. Findings 1 and 3 concern routes outside that protection. |
| `79418b3` path handling | Both lexical and physical readings are checked. Existing regular hard links are refused for explicit write targets. The specific link-before-`..` gap is addressed. |
| `79418b3` Codex roots | Direct `-C`/`--add-dir` targets inside the main checkout’s `.git` or protected trees are rejected after canonicalization. |
| `79418b3` Cursor | Native `beforeShellExecution` and `Shell` events remain unsandboxed regardless of a model field. Live Cursor registration and refusal behavior remain unverified. |
| `db3ec47` | Moving decision tests into the hook package removes their dependency on the outer suite’s profile-applying `TestMain`. I found no production-policy change in this commit. |
| `92ba228` | Generates the documented policy structure and installs it root-owned. Its text tests establish generation/check behavior, not Codex enforcement. |
| `local.sb` | Contains protected-tree denies and explicit ancestor-directory denies. The drift test checks those lists. Runtime enforcement was not rerun. |

The working tree remained clean. The initial system Git shim attempted an Xcode cache write that the sandbox denied; subsequent reads used the underlying Git binary with optional locks disabled.

**Final verdict: block approval until the demonstrated bypasses and installer defects are closed; the current evidence does not establish Codex 0.160 enforcement.**


Codex session ID: 01a1a426-ef76-7db2-8b8a-95cafe839118
Resume in Codex: codex resume 01a1a426-ef76-7db2-8b8a-95cafe839118
