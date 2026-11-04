// The hook's decision tests, moved here from the containment suite (containment/go/hook_test.go)
// on 2026-11-03: they apply no profile, and that suite's TestMain writes a Seatbelt profile and
// applies it, which no sandbox permits, so they could run only in the owner's terminal and an agent
// change to the hook went untested until install. In package hook_test they build into the hook
// package's binary, which runs under d1-nonet from d1preservation. TestHookBinary stays there: it
// builds the hook with go build.
package hook_test

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"d1preservation/netguard/gate"
	"d1preservation/netguard/hook"
)

// writeTree creates each named file under root. Under d1-nonet the game profile refuses to write
// any file named *.sb (so no profile can be rewritten), so the protected profiles are left out
// there; a protected file that is absent is refused by the hook all the same (creating it is a
// write of it). Any other failure fails the test.
func writeTree(t *testing.T, root string, names []string) {
	t.Helper()
	for _, name := range names {
		path := filepath.Join(root, name)
		err := os.MkdirAll(filepath.Dir(path), 0o700)
		if err == nil {
			err = os.WriteFile(path, []byte("fake\n"), 0o600)
		}
		if err != nil && !(strings.HasSuffix(name, ".sb") && errors.Is(err, fs.ErrPermission)) {
			t.Fatal(err)
		}
	}
}

// fakeHookTree builds a repository holding every protected file and two unprotected ones, a home
// directory with .claude/settings.json, and a launcher directory holding the three binaries as
// files (owned by the test's user, so never trusted). AGENTS.md is left absent.
func fakeHookTree(t *testing.T) hook.Config {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	config := hook.Config{Root: filepath.Join(base, "repo"), Home: filepath.Join(base, "home"), LauncherDirectory: filepath.Join(base, "libexec", "d1-agent")}
	var files []string
	for _, name := range gate.ProtectedFiles {
		if name != "AGENTS.md" {
			files = append(files, filepath.Join("repo", name))
		}
	}
	files = append(files, "repo/notes.md", "repo/containment/notes.md", "home/.claude/settings.json")
	for _, name := range []string{"d1-nonet", "d1-localonly", "d1-agent-hook"} {
		files = append(files, filepath.Join("libexec", "d1-agent", name))
	}
	writeTree(t, base, files)
	return config
}

// bashEvent is a Bash PreToolUse event from an elevated model's session (Codex's model field), so
// these tests reach the forms of the excluded programs; what every other model gets is
// TestAccessMatrix's (hook/matrix_test.go).
func bashEvent(t *testing.T, command string, sandboxOff bool, cwd string) []byte {
	t.Helper()
	input := map[string]any{"command": command, "description": "test"}
	if sandboxOff {
		input["dangerouslyDisableSandbox"] = true
	}
	return marshal(t, map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": input, "cwd": cwd, "model": "gpt-6.1-sol"})
}

// editEvent is an edit-tool PreToolUse event for one path.
func editEvent(t *testing.T, tool string, path string, cwd string) []byte {
	t.Helper()
	field := "file_path"
	if tool == "NotebookEdit" {
		field = "notebook_path"
	}
	return marshal(t, map[string]any{"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": map[string]any{field: path}, "cwd": cwd})
}

// marshal is json.Marshal that fails the test on error.
func marshal(t *testing.T, value any) []byte {
	t.Helper()
	text, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return text
}

// TestHookLauncherForm: the sandbox-off command shape, admitted and refused, with the reason named.
func TestHookLauncherForm(t *testing.T) {
	config := fakeHookTree(t)
	nonet := config.LauncherDirectory + "/d1-nonet"
	localonly := config.LauncherDirectory + "/d1-localonly"
	release := config.Root + "/d1-server/target/release/"
	alias := filepath.Join(filepath.Dir(config.Root), "alias")
	err := os.Symlink(config.LauncherDirectory, alias)
	if err != nil {
		t.Fatal(err)
	}
	admitted := []string{
		nonet + " " + release + "d1-recomp run --program /x/emit --seconds 20 --log /x/runs/r1/run.txt",
		"D1_EBOOT=/x/eboot.elf D1_GFX=/x/libd1gfx.dylib " + nonet + " " + release + "d1-oracle --help",
		nonet + " " + release + "deps/d1_activity_host-60a8a830d1ed6526 --skip pinned --test-threads=1",
		"D1_EBOOT=/x/eboot.elf " + nonet + " " + config.Root + "/d1-server/target/debug/deps/d1_oracle-0123456789abcdef",
		nonet + " " + config.Root + "/testbin/server.test -test.run TestWallet",
		nonet + " " + config.Root + "/testbin/d1-save_v2.test",
		localonly + " /opt/homebrew/bin/cargo build -p d1-responder",
		localonly + " " + release + "d1-responder --bind 127.0.0.1",
	}
	for _, command := range admitted {
		launcher, why := hook.LauncherForm(command, config)
		if why != "" || !strings.HasPrefix(launcher, config.LauncherDirectory+"/") {
			t.Errorf("refused %q: %s", command, why)
		}
	}
	refused := map[string]string{
		release + "d1-recomp run":                                                   "is not a launcher",
		alias + "/d1-nonet " + release + "d1-recomp":                                "is not a launcher",
		config.LauncherDirectory + "/../d1-agent/d1-nonet " + release + "d1-recomp": "is not a launcher",
		config.LauncherDirectory + "//d1-nonet " + release + "d1-recomp":            "is not a launcher",
		nonet + " " + release + "d1-recomp run; curl http://1.1.1.1":                "';' is not allowed",
		nonet + " " + release + "d1-recomp && sh":                                   "'&' is not allowed",
		nonet + " " + release + "d1-recomp | sh":                                    "'|' is not allowed",
		nonet + " " + release + "d1-recomp > /tmp/x":                                "'>' is not allowed",
		nonet + " $(echo x)":                                                        "'$' is not allowed",
		nonet + " `id`":                                                             "'`' is not allowed",
		nonet + " \"a b\"":                                                          "is not allowed",
		nonet + " " + release + "d1-recomp\ncurl x":                                 "is not allowed",
		"D1_NET_SOCKETS=1 " + nonet + " " + release + "d1-recomp":                   "D1_NET_SOCKETS may not be set",
		"D1_NETGUARD_FD=3 " + nonet + " " + release + "d1-recomp":                   "D1_NETGUARD_FD may not be set",
		"DYLD_INSERT_LIBRARIES=/x.dylib " + nonet + " " + release + "d1-recomp":     "DYLD_INSERT_LIBRARIES may not be set",
		"GODEBUG=inittrace=1 " + nonet + " " + release + "d1-recomp":                "GODEBUG may not be set",
		"PATH=/x " + localonly + " /bin/ls":                                         "PATH may not be set",
		nonet + " /bin/sh -c x":                                                     "runs only a game binary",
		nonet + " " + release + "d1-responder":                                      "runs only a game binary",
		nonet + " /elsewhere/d1-server/target/release/d1-recomp":                    "runs only a game binary",
		nonet + " " + release + "deps/libd1_oracle-60a8a830d1ed6526.rlib":           "runs only a game binary",
		nonet + " " + release + "deps/d1_oracle-60a8a830d1ed652":                    "runs only a game binary",
		nonet + " " + release + "deps/d1_oracle-60A8A830D1ED6526":                   "runs only a game binary",
		nonet + " " + release + "deps/../deps/d1_oracle-60a8a830d1ed6526":           "runs only a game binary",
		nonet + " /elsewhere/target/release/deps/d1_oracle-60a8a830d1ed6526":        "runs only a game binary",
		nonet + " " + config.Root + "/testbin/server":                               "runs only a game binary",
		nonet + " " + config.Root + "/testbin/.test":                                "runs only a game binary",
		nonet + " " + config.Root + "/testbin/sub/server.test":                      "runs only a game binary",
		nonet + " /elsewhere/testbin/server.test":                                   "runs only a game binary",
		localonly + " " + release + "d1-recomp run":                                 "never a game binary",
		localonly + " /opt/homebrew/bin/cargo test -p d1-responder":                 "tests run only under d1-nonet",
		localonly + " /opt/homebrew/bin/cargo t":                                    "tests run only under d1-nonet",
		localonly + " /usr/local/go/bin/go test ./...":                              "tests run only under d1-nonet",
		localonly + " " + config.Root + "/testbin/server.test":                      "tests run only under d1-nonet",
		localonly + " /x/elsewhere.test":                                            "tests run only under d1-nonet",
		localonly + " " + release + "deps/d1_bap-60a8a830d1ed6526":                  "tests run only under d1-nonet",
		localonly + " cargo test":                                                   "absolute path",
		nonet:                                                                       "run a launcher followed by",
		"D1_X=1":                                                                    "run a launcher followed by",
		"":                                                                          "run a launcher followed by",
		"/bin/sh":                                                                   "is not a launcher",
	}
	for command, reason := range refused {
		_, why := hook.LauncherForm(command, config)
		if !strings.Contains(why, reason) {
			t.Errorf("%q: wanted a refusal naming %q, got %q", command, reason, why)
		}
	}
}

// TestHookBash: the Bash rules end to end through Decide, in and out of the repository's scope.
func TestHookBash(t *testing.T) {
	config := fakeHookTree(t)
	inside := config.Root
	outside := config.Home
	nonet := config.LauncherDirectory + "/d1-nonet " + config.Root + "/d1-server/target/release/d1-recomp run --seconds 5"
	codexHeredoc := "codex exec -s read-only -C \"$PWD\" -o docs/r.md - <<'EOF' > \"$TMPDIR/codex.log\" 2>&1\n" +
		"d1-recomp spawns clang; review it | carefully & say $(why) `now`\nEOF\n"
	codexContinued := "/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex exec -m gpt-6.1-sol \\\n" +
		"  -c model_reasoning_effort='\"high\"' -s read-only -C \"$PWD\" --ephemeral --color never \\\n" +
		"  -o docs/research/r.md - <<'EOF' > \"$TMPDIR/codex.log\" 2>&1\nthe task\nEOF"
	companionPath := "/Users/ryanheffernan/.claude/plugins/cache/openai-codex/codex/1.0.6/scripts/codex-companion.mjs"
	companion := "node " + companionPath
	cases := []struct {
		command    string
		sandboxOff bool
		cwd        string
		reason     string // "" means admitted
	}{
		{companion + " setup --json", false, inside, ""},
		{companion + " task --write \"fix the model\"", true, inside, ""},
		{"node \"" + companionPath + "\" status \"$ARGUMENTS\"", false, inside, ""},
		{companion + " review", true, inside, "reviews start ephemeral threads"},
		{companion + " adversarial-review x", true, inside, "reviews start ephemeral threads"},
		{companion + " task x && curl y", true, inside, "\"&\" starts another command"},
		{companion + " task x; curl y", true, inside, "\";\" starts another command"},
		{companion + " task $(curl x)", true, inside, "can run another command"},
		{"node /tmp/codex-companion.mjs task x", true, inside, "runs only as node on its installed script"},
		{"node \"${CLAUDE_PLUGIN_ROOT}/scripts/codex-companion.mjs\" task x", true, inside, "runs only as node on its installed script"},
		{"node other.js", true, inside, "is not a launcher"},
		{"ls -la", false, inside, ""},
		// Tests run inside the game profile, and a plain "go test" inside the agent sandbox used to
		// pass (audit 2026-10-31, N7). The build-then-launch forms stay admitted, below.
		{"go test ./...", false, inside, "would run tests inside the agent sandbox"},
		{"go test -run TestX ./internal/sched", false, inside, "would run tests inside the agent sandbox"},
		{"cd tools/d1 && go test ./internal/...", false, inside, "would run tests inside the agent sandbox"},
		{"cargo test -p d1-bap", false, inside, "would run tests inside the agent sandbox"},
		{"cargo nextest run -p d1-bap", false, inside, "would run tests inside the agent sandbox"},
		{"cargo bench -p d1-bap", false, inside, "would run tests inside the agent sandbox"},
		{"go test ./...", false, outside, ""},
		{"go build ./...", false, inside, ""},
		{"go vet ./...", false, inside, ""},
		{"cargo build -p d1-recomp", false, inside, ""},
		{nonet, true, inside, "cannot be trusted"},
		{"/usr/bin/true", true, inside, "is not a launcher"},
		{"/usr/bin/true", true, outside, ""},
		{config.Root + "/d1-server/target/release/d1-recomp run", false, inside, "runs game code"},
		{"cd x && ./d1-oracle --help", false, outside, "runs game code"},
		{"D1_X=1 d1-replay capture", true, outside, "runs game code"},
		{"xcrun --show-sdk-path", true, inside, ""},
		{"xcrun --show-sdk-path", false, inside, ""},
		{"/usr/bin/security find-identity -p codesigning", true, inside, ""},
		{"/usr/bin/security find-certificate -a", true, inside, "security find-identity"},
		{"/usr/bin/log show --last 1m", false, inside, ""},
		{"log show --last 1m", false, inside, "its own path"},
		{codexHeredoc, true, inside, ""},
		{codexContinued, true, inside, ""},
		{"xcrun true; curl http://1.1.1.1", false, inside, "\";\" starts another command"},
		{"xcrun true; curl http://1.1.1.1", false, outside, ""},
		{"codex exec x && curl y", true, inside, "\"&\" starts another command"},
		{"cd App && xcodebuild build", false, inside, "\"&\" starts another command"},
		{"cd App; xcodebuild build", false, outside, ""},
		{"security find-generic-password -w | pbcopy", false, inside, "\"|\" starts another command"},
		{"xcrun $(curl x)", false, inside, "can run another command"},
		{"xcrun `id`", false, inside, "can run another command"},
		{"xcrun \"unclosed", false, inside, "an unclosed quote"},
		{"codex exec - <<EOF\n$(curl x)\nEOF", true, inside, "must be quoted"},
		{"codex exec - <<'EOF'\nbody", true, inside, "never ends"},
		{"codex exec - <<'EOF'\nbody\nEOF\ncurl x", true, inside, "a line after the heredoc"},
		{"codex exec - << 'EOF'\nbody\nEOF", true, inside, ""},
		{"codex exec - <<-'EOF'\nbody\n\tEOF", true, inside, ""},
		{"codex exec - <<'E-F'\nbody\nE-F", true, inside, "one quoted word of letters"},
		{"codex exec - <<'EOF' <<'EOF'\nbody\nEOF", true, inside, "a second heredoc"},
		{"xcrun true\ncurl x", false, inside, "a second line"},
		{"/tmp/codex exec x", true, inside, "must start with it"},
		{"codex login", true, inside, "only codex exec"},
		{"/usr/bin/log erase --all", false, inside, "is not one of the admitted"},
		{"log erase --all", false, inside, "its own path"},
		// copilot: the pinned path is gone and "--allow-tool shell" is --allow-all by another name
		// (audit 2026-10-31, N3), so every form is refused until the owner pins a path again.
		{"copilot -p \"read the docs\" --model auto --no-ask-user --allow-tool 'shell(d1-server/target/release/d1-eboot)'", true, inside, "copilot is not excluded from the sandbox"},
		{"/Users/ryanheffernan/.nvm/versions/node/v22.19.0/bin/copilot -p x --allow-tool 'shell(ls)'", true, inside, "copilot is not excluded from the sandbox"},
		{"copilot -p x --allow-all", true, inside, "copilot is not excluded from the sandbox"},
		{"copilot -p x --yolo", true, inside, "copilot is not excluded from the sandbox"},
		{"copilot login", true, inside, "copilot is not excluded from the sandbox"},
		{"/tmp/copilot -p x", true, inside, "must start with it"},
		{"copilot -p x && curl y", true, inside, "\"&\" starts another command"},
		// codex keeps its own sandbox and hook trust, and writes its output inside the repository
		// (audit N2 and N3): before this, every one of these ran outside every sandbox.
		{"codex exec --dangerously-bypass-approvals-and-sandbox 'do it'", true, inside, "turns off the sandbox"},
		{"codex exec --dangerously-bypass-hook-trust 'do it'", true, inside, "turns off the sandbox"},
		{"codex exec --yolo 'do it'", true, inside, "turns off the sandbox"},
		{"codex exec -c sandbox_mode=danger-full-access 'do it'", true, inside, "is not admitted"},
		{"codex exec --config sandbox_mode=\"danger-full-access\" 'do it'", true, inside, "is not admitted"},
		{"codex exec -s danger-full-access 'do it'", true, inside, "is not admitted"},
		{"codex exec -s workspace-write 'do it'", true, inside, ""},
		{"codex exec -c model_reasoning_effort='\"xhigh\"' -s read-only 'do it'", true, inside, ""},
		{"codex exec -s read-only -o " + config.Home + "/.zshrc -", true, inside, "writes its output inside"},
		{"codex exec -s read-only -o docs/research/r.md -", true, inside, ""},
		{"xcodebuild -version > " + config.Root + "/CLAUDE.md", true, inside, "which is protected"},
		{"security find-identity > CLAUDE.md", true, inside, "which is protected"},
		{"codex exec -s read-only -o " + config.Home + "/.claude/settings.json -", true, inside, "is protected"},
		{"system_profiler SPHardwareDataType > containment/go/profiles/game.sb", true, inside, "which is protected"},
		{"cargo test --no-run -p d1-bap", false, inside, ""},
		{"go test -c -o testbin/ ./internal/...", false, inside, ""},
		{"cmake --build . --config Release", false, inside, ""},
		{"RUSTFLAGS= cargo test", false, inside, "without the test gate"},
		{"env RUSTFLAGS=-Cdebuginfo=1 cargo build", false, inside, "without the test gate"},
		{"export CARGO_ENCODED_RUSTFLAGS=x", false, inside, "without the test gate"},
		{"CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS=x cargo test", false, inside, "without the test gate"},
		{"CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=/x/ld cargo test", false, inside, "without the test gate"},
		{"CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER=/bin/sh cargo test", false, inside, "without the test gate"},
		{"RUSTDOCFLAGS='' cargo test --doc", false, inside, "without the test gate"},
		{"RUSTC_WRAPPER=/x/w cargo test", false, inside, "without the test gate"},
		{"RUSTC=/x/rustc cargo test", false, inside, "without the test gate"},
		{"CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=/x cargo test", false, inside, "without the test gate"},
		{"cargo test --config build.rustflags=[]", false, inside, "without the test gate"},
		{"cargo --config=x.toml test", false, inside, "without the test gate"},
		{"RUSTFLAGS= cargo test", false, outside, ""},
	}
	for _, test := range cases {
		why := hook.Decide(bashEvent(t, test.command, test.sandboxOff, test.cwd), test.cwd, config)
		if test.reason == "" && why != "" || test.reason != "" && !strings.Contains(why, test.reason) {
			t.Errorf("%q (sandbox off %v, in %s): wanted %q, got %q", test.command, test.sandboxOff, test.cwd, test.reason, why)
		}
	}
}

// TestHookTripwire: in sessions in scope, a Bash command naming a protected file (any case) is
// admitted only as a pure read; out of scope the same text is admitted. A tripwire, spelling-based.
func TestHookTripwire(t *testing.T) {
	config := fakeHookTree(t)
	inside := config.Root
	outside := config.Home
	refused := "which is protected, and is not a pure read"
	codex := "/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex exec -m gpt-6-astra -s read-only --ephemeral - <<'EOF' > log 2>&1\n" +
		"Read CLAUDE.md and containment/go/profiles/game.sb, then review game.sb.\nEOF"
	cases := []struct {
		command string
		cwd     string
		reason  string // "" means admitted
	}{
		{"cat CLAUDE.md", inside, ""},
		{"grep -n x containment/go/profiles/game.sb | head", inside, ""},
		{"git log -p -- containment/go/hook/hook.go", inside, ""},
		{"cat d1-server/.cargo/config.toml ~/.claude/settings.json", inside, ""},
		{"sed -i '' s/a/b/ d1-server/crates/d1-eboot/src/main.rs", inside, ""},
		{"sed -i '' s/a/b/ CLAUDE.md", inside, "names CLAUDE.md, " + refused},
		{"python3 - <<'EOF'\nopen('CLAUDE.md', 'w')\nEOF", inside, "names CLAUDE.md, " + refused + " (\"<\" reads a file"},
		{"python3 -c \"open('CLAUDE.md', 'w')\"\n", inside, "a newline, so a second command or a heredoc"},
		{"echo x > containment/c/d1netgate.c", inside, "names containment/c/d1netgate.c, " + refused},
		{"cat notes.md | tee CLAUDE.md", inside, "\"tee\" writes a file"},
		{"cat /usr/bin/tee CLAUDE.md", inside, "\"tee\" writes a file"},
		// Read as bash reads it (F5 of the 2026-10-27 review): a quoted or escaped pipe is text, a
		// descriptor merge writes no file, and "tee" inside a word is not tee. Each of these was
		// refused before, and 438 of 849 refusals in the logs were of this kind.
		{"grep -n -E 'alpha|beta' containment/c/d1netgate.c | head", inside, ""},
		{"grep -n 'a|b' CLAUDE.md", inside, ""},
		{"grep -n a\\|b CLAUDE.md", inside, ""},
		{"grep -n steering containment/agent-containment.md", inside, ""},
		{"grep -c committee CLAUDE.md", inside, ""},
		{"cat CLAUDE.md 2>&1 | head -40", inside, ""},
		{"git -C " + inside + " log --oneline -3 -- containment/go 2>&1 | wc -l", inside, ""},
		{"grep -rn \"d1-nonet\" containment/go | head", inside, ""},
		{"grep -n 'x' CLAUDE.md | tee out.txt", inside, "\"tee\" writes a file"},
		{"cat CLAUDE.md > out.txt", inside, "\">\" writes a file"},
		{"cat CLAUDE.md && rm -rf x", inside, "\"&\" starts another command"},
		{"cat CLAUDE.md || true", inside, "\"||\" starts another command"},
		{"cat \"$(ls CLAUDE.md)\"", inside, "\"$(\" runs another command"},
		{"cat 'CLAUDE.md", inside, "an unclosed quote"},
		// The protected trees: a file nobody listed, and the tree's own path (audit N1 and N4).
		{"echo x > containment/go/hook/planted_test.go", inside, "names containment/go, " + refused},
		{"cp /tmp/x containment/go/go.mod", inside, "names containment/go, " + refused},
		{"echo x > .claude/hooks/owner-inbox.sh", inside, "names .claude/hooks, " + refused},
		{"cp /tmp/x .git/hooks/pre-commit", inside, "names .git/hooks, " + refused},
		{"chmod +x .git/hooks/post-checkout", inside, "names .git/hooks, " + refused},
		{"cat containment/go/hook/matrix.go", inside, ""},
		{"ls -la containment/go/hook", inside, ""},
		{"sed -i '' s/a/b/ Claude.MD", inside, "names CLAUDE.md, " + refused},
		{"perl -pi -e s/a/b/ ~/.claude/settings.json", inside, "names .claude/settings.json, " + refused},
		{"perl -pi -e s/a/b/ d1-server/.cargo/config.toml", inside, "names d1-server/.cargo/config.toml, " + refused},
		{"sed -i '' s/a/b/ d1-server/crates/d1-recomp/src/main.rs", inside, "names d1-server/crates/d1-recomp/src/main.rs, " + refused},
		{"git diff --output=CLAUDE.md", inside, refused},
		{"rg --pre sh x CLAUDE.md", inside, refused},
		{"PATH=/private/tmp/x cat CLAUDE.md", inside, refused},
		{"/private/tmp/x/cat CLAUDE.md", inside, refused},
		{"sed -i '' s/a/b/ " + outside + "/other/claude.md", outside, ""},
		{"git -C " + inside + " log --oneline -3 -- containment/c/d1netgate.c", inside, ""},
		{"git show HEAD:CLAUDE.md", inside, ""},
		{"git diff --output=x CLAUDE.md", inside, "names CLAUDE.md, " + refused},
		{"git -c core.editor=x log CLAUDE.md", inside, "names CLAUDE.md, " + refused},
		{"git log -c CLAUDE.md", inside, "names CLAUDE.md, " + refused},
		{"git -C " + inside + " -c core.pager=x log CLAUDE.md", inside, "names CLAUDE.md, " + refused},
		{"git diff --ext-diff CLAUDE.md", inside, "names CLAUDE.md, " + refused},
		{"git checkout -- CLAUDE.md", inside, "names CLAUDE.md, " + refused},
		{"git add CLAUDE.md", inside, "names CLAUDE.md, " + refused},
		{"git -C CLAUDE.md", inside, "names CLAUDE.md, " + refused},
		{codex, inside, ""},
		{codex + "\n; sed -i '' s/a/b/ CLAUDE.md", inside, "must be that program alone"},
	}
	for _, test := range cases {
		why := hook.Decide(bashEvent(t, test.command, false, test.cwd), test.cwd, config)
		if test.reason == "" && why != "" || test.reason != "" && !strings.Contains(why, test.reason) {
			t.Errorf("%q (in %s): wanted %q, got %q", test.command, test.cwd, test.reason, why)
		}
		// Every tripwire refusal states the allowed form, not only the doc: the reading programs and
		// the Read tool, then the two ways to change the file (F7 of the 2026-10-27 review).
		if test.reason != "" && !strings.Contains(test.reason, "program alone") {
			for _, wanted := range []string{"To read it: the Read tool", "cat, head, tail, grep", "To change it: show the owner the change (containment/agent-containment.md, point 5)", "scratchpad window directory"} {
				if !strings.Contains(why, wanted) {
					t.Errorf("%q: the refusal does not say %q: %q", test.command, wanted, why)
				}
			}
		}
	}
}

// TestHookEdits: edits of protected files are refused from any session, however the path is
// spelled: directly, relative, through a symbolic link, in another case, through a hard link, a
// link to nothing, a non-ASCII lookalike; edits of the files beside them are admitted.
func TestHookEdits(t *testing.T) {
	config := fakeHookTree(t)
	base := filepath.Dir(config.Root)
	links := map[string]string{"repo-link": config.Root, "claude-link": config.Root + "/CLAUDE.md", "agents-link": config.Root + "/AGENTS.md"}
	for name, target := range links {
		err := os.Symlink(target, filepath.Join(base, name))
		if err != nil {
			t.Fatal(err)
		}
	}
	hardLink := filepath.Join(base, "hard-link")
	err := os.Link(config.Root+"/containment/go/gate/gate.go", hardLink)
	if err != nil {
		t.Fatal(err)
	}
	refused := append(hook.ProtectedPaths(config), base+"/repo-link/CLAUDE.md", base+"/claude-link", base+"/agents-link", hardLink,
		config.Root+"/claude.md", config.Root+"/Containment/Go/Profiles/LOCAL.SB", base+"/REPO-LINK/agents.md",
		config.Root+"/containment/go/cmd/../profiles/./game.sb", config.Root+"/ag\u0130nts.md", config.Home+"/.CLAUDE/Settings.json")
	for _, path := range refused {
		why := hook.Decide(editEvent(t, "Edit", path, "/"), "", config)
		if !strings.Contains(why, "Edit of "+path+" refused: ") {
			t.Errorf("an edit of %s was not refused: %q", path, why)
		}
	}
	tools := map[string]string{"Write": "CLAUDE.md", "MultiEdit": "containment/c/d1netgate.c", "NotebookEdit": "AGENTS.md"}
	for tool, relative := range tools {
		why := hook.Decide(editEvent(t, tool, relative, config.Root), config.Root, config)
		if !strings.Contains(why, "is protected") {
			t.Errorf("%s of %s relative to the repository was not refused: %q", tool, relative, why)
		}
	}
	// The protected trees: a file nobody has listed yet, in the tree or in a worktree's copy of it,
	// is refused as well (audit 2026-10-31, N1, N4 and N6). install.sh builds and tests
	// containment/go as the owner, and git and Claude Code run what is in a hooks directory.
	trees := []string{
		config.Root + "/containment/go/new.go",
		config.Root + "/containment/go/hook/planted_test.go",
		config.Root + "/containment/go/go.mod",
		config.Root + "/containment/go/.gocache/00/x-a",
		config.Root + "/Containment/GO/hook/Matrix.go",
		config.Root + "/containment/c/extra.c",
		config.Root + "/.claude/hooks/owner-inbox.sh",
		config.Root + "/.git/hooks/pre-commit",
		config.Root + "/.claude/worktrees/wt1/d1-server/crates/d1-recomp/src/main.rs",
		config.Root + "/.claude/worktrees/wt1/containment/go/hook/hook.go",
		config.Root + "/runs/wt-gfx/d1-server/crates/d1-recomp/build.rs",
		config.Root + "/runs/wt-gfx/CLAUDE.md",
	}
	for _, path := range trees {
		why := hook.Decide(editEvent(t, "Edit", path, "/"), "", config)
		if !strings.Contains(why, "Edit of "+path+" refused: ") {
			t.Errorf("an edit of %s was not refused: %q", path, why)
		}
	}
	for _, path := range []string{config.Root + "/notes.md", config.Root + "/Containment/Notes.md", config.Root + "/containment/reviews/new.md",
		config.Root + "/runs/hookstage/notes.md", config.Root + "/.claude/worktrees/wt1/spec/README.md", config.Root + "/runs/wt-gfx/tools/d1/main.go",
		base + "/repo-link/new.md", config.Home + "/.claude/projects/repo/memory/fact.md"} {
		why := hook.Decide(editEvent(t, "Edit", path, "/"), "", config)
		if why != "" {
			t.Errorf("an edit of %s was refused: %q", path, why)
		}
	}
}

// patchEvent is a Codex apply_patch PreToolUse event: the patch text is tool_input.command.
func patchEvent(t *testing.T, patch string, cwd string) []byte {
	t.Helper()
	return marshal(t, map[string]any{"hook_event_name": "PreToolUse", "tool_name": "apply_patch", "tool_input": map[string]any{"command": patch}, "cwd": cwd})
}

// TestHookPatches: a Codex apply_patch that adds, changes, deletes or renames to a protected file
// is refused, absolute or relative, wherever it sits in a multi-file patch; one that touches only
// other files is admitted; a marker inside a hunk's content is not a file line.
func TestHookPatches(t *testing.T) {
	config := fakeHookTree(t)
	patch := func(lines ...string) string {
		return "*** Begin Patch\n" + strings.Join(lines, "\n") + "\n*** End Patch\n"
	}
	refused := map[string]string{
		"update, absolute":    patch("*** Update File: "+config.Root+"/CLAUDE.md", "@@", "-a", "+b"),
		"add, relative":       patch("*** Add File: AGENTS.md", "+text"),
		"delete":              patch("*** Delete File: containment/go/profiles/game.sb"),
		"rename onto":         patch("*** Update File: notes.md", "*** Move to: containment/c/d1netgate.c", "@@", "-a", "+b"),
		"second of two files": patch("*** Update File: notes.md", "@@", "-a", "+b", "*** Update File: containment/go/gate/local.go", "@@", "-a", "+b"),
		"a file in a tree":    patch("*** Add File: containment/go/hook/planted_test.go", "+package hook"),
		"a worktree's copy":   patch("*** Update File: .claude/worktrees/wt1/containment/c/d1netgate.c", "@@", "-a", "+b"),
		"other case":          patch("*** Update File: Claude.MD", "@@", "-a", "+b"),
		"owner settings":      patch("*** Update File: "+config.Home+"/.claude/settings.json", "@@", "-a", "+b"),
	}
	for name, text := range refused {
		why := hook.Decide(patchEvent(t, text, config.Root), "", config)
		if !strings.Contains(why, "apply_patch of ") || !strings.Contains(why, "refused: ") {
			t.Errorf("%s: the patch was not refused: %q", name, why)
		}
	}
	admitted := map[string]string{
		"one file":         patch("*** Update File: notes.md", "@@", "-a", "+b"),
		"new file":         patch("*** Add File: containment/reviews/new.md", "+text"),
		"marker in a hunk": patch("*** Update File: notes.md", "@@", "-old", "+*** Update File: CLAUDE.md"),
	}
	for name, text := range admitted {
		why := hook.Decide(patchEvent(t, text, config.Root), "", config)
		if why != "" {
			t.Errorf("%s: the patch was refused: %q", name, why)
		}
	}
	for name, raw := range map[string]string{
		"no command":  `{"tool_name":"apply_patch","tool_input":{}}`,
		"no file":     `{"tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** End Patch\n"},"cwd":"/"}`,
		"empty path":  `{"tool_name":"apply_patch","tool_input":{"command":"*** Update File: \n"},"cwd":"/"}`,
		"no cwd, rel": `{"tool_name":"apply_patch","tool_input":{"command":"*** Update File: notes.md\n"}}`,
	} {
		if hook.Decide([]byte(raw), "", config) == "" {
			t.Errorf("%s: the patch event was admitted", name)
		}
	}
}

// TestHookFailsClosed: every event the hook cannot read, and every tool it does not decide, is refused.
func TestHookFailsClosed(t *testing.T) {
	config := fakeHookTree(t)
	for _, raw := range []string{
		"", "not json", "{}", "[]", `{"tool_name":"Bash"}`, `{"tool_name":"Bash","tool_input":{}}`,
		`{"tool_name":"Bash","tool_input":{"command":5}}`,
		`{"tool_name":"Bash","tool_input":{"command":"ls","dangerouslyDisableSandbox":"yes"}}`,
		`{"tool_name":"Edit","tool_input":{}}`, `{"tool_name":"Edit","tool_input":{"file_path":7}}`,
		`{"tool_name":"Read","tool_input":{"file_path":"/x"}}`,
		`{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`,
	} {
		if hook.Decide([]byte(raw), config.Root, config) == "" {
			t.Errorf("the event %q was admitted", raw)
		}
	}
	if hook.Decide([]byte(`{"tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/","model":"gpt-6.1-sol"}`), config.Root, config) != "" {
		t.Error("the positive control, a plain sandboxed ls from a harness that sandboxes it, was refused")
	}
}

// TestHookHarnesses: the event shapes the hook reads, and what each one gets. Claude Code and Codex
// say which sandbox a call runs in (transcript_path, model), so their sandboxed calls pass. Cursor
// says nothing and sandboxes nothing: its two spellings of PreToolUse, its native
// beforeShellExecution with the command at the top level, and its Shell tool name are all read, and
// every command from them is decided as if the sandbox were off (the 2026-10-27 review, §2; the
// owner's flag on Decide). An event the hook cannot place is still refused.
func TestHookHarnesses(t *testing.T) {
	config := fakeHookTree(t)
	nonet := config.LauncherDirectory + "/d1-nonet " + config.Root + "/testbin/server.test"
	cases := []struct {
		name, raw, reason string
	}{
		{"Claude Code, sandboxed", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"` + config.Root + `","transcript_path":"/nowhere/t.jsonl"}`, ""},
		{"Codex, sandboxed", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"` + config.Root + `","model":"gpt-6.1-sol"}`, ""},
		{"Cursor, Claude-hook import", `{"hook_event_name":"preToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"cwd":""}`, "is not a launcher"},
		{"Cursor, Shell tool", `{"hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"ls"},"cwd":""}`, "is not a launcher"},
		{"Cursor, native event", `{"hook_event_name":"beforeShellExecution","command":"ls","cwd":""}`, "is not a launcher"},
		{"Cursor, native event, launcher", `{"hook_event_name":"beforeShellExecution","command":"` + nonet + `","cwd":""}`, "cannot be trusted"},
		{"Cursor, native event, game binary", `{"hook_event_name":"beforeShellExecution","command":"d1-recomp run","cwd":""}`, "runs game code"},
		{"Cursor, protected file", `{"hook_event_name":"beforeShellExecution","command":"sed -i '' s/a/b/ CLAUDE.md","cwd":"` + config.Root + `"}`, "which is protected"},
		{"an event this hook does not decide", `{"hook_event_name":"afterFileEdit","tool_name":"Bash","tool_input":{"command":"ls"}}`, "and was sent afterFileEdit"},
		{"a tool this hook does not decide", `{"hook_event_name":"preToolUse","tool_name":"WebFetch","tool_input":{"url":"x"}}`, "and was sent \"WebFetch\""},
	}
	for _, test := range cases {
		why := hook.Decide([]byte(test.raw), config.Root, config)
		if test.reason == "" && why != "" || test.reason != "" && !strings.Contains(why, test.reason) {
			t.Errorf("%s: wanted %q, got %q", test.name, test.reason, why)
		}
		if strings.Contains(test.name, "Cursor") && test.reason == "is not a launcher" && !strings.Contains(why, "neither transcript_path nor model") {
			t.Errorf("%s: the refusal does not say why the call is treated as unsandboxed: %q", test.name, why)
		}
	}
}

// TestHookReachesIn: a session working elsewhere meets this repository's rules when the command
// spells its root, and nothing else changes for it (audit 2026-10-31, N9, and F2 of 2026-10-27:
// a sandbox-off "cp x <repo>/CLAUDE.md" from another project passed).
func TestHookReachesIn(t *testing.T) {
	config := fakeHookTree(t)
	outside := config.Home // a sibling of the repository: neither inside it nor above it
	cases := []struct {
		command    string
		sandboxOff bool
		reason     string
	}{
		{"cp x " + config.Root + "/CLAUDE.md", true, "which is protected"},
		{"cp x " + config.Root + "/CLAUDE.md", false, "which is protected"},
		{"cat " + config.Root + "/CLAUDE.md", false, ""},
		{"echo x > " + config.Root + "/containment/go/hook/planted_test.go", false, "which is protected"},
		{"cd " + config.Root + "/tools/d1 && go test ./internal/...", false, "would run tests inside the agent sandbox"},
		{"curl http://example.com", true, ""},
		{"git push", true, ""},
		{"cp x y", false, ""},
	}
	for _, test := range cases {
		why := hook.Decide(bashEvent(t, test.command, test.sandboxOff, outside), outside, config)
		if test.reason == "" && why != "" || test.reason != "" && !strings.Contains(why, test.reason) {
			t.Errorf("%q (sandbox off %v, in %s): wanted %q, got %q", test.command, test.sandboxOff, outside, test.reason, why)
		}
	}
}

// TestHookRootOwned: /usr/bin/true is root-owned all the way up; the fake launcher is not.
func TestHookRootOwned(t *testing.T) {
	config := fakeHookTree(t)
	if why := hook.RootOwned("/usr/bin/true"); why != "" {
		t.Fatalf("the positive control /usr/bin/true was not root-owned: %s", why)
	}
	if hook.RootOwned(config.LauncherDirectory+"/d1-nonet") == "" {
		t.Fatal("a launcher owned by the test's user was trusted")
	}
}

// TestHookSettingsAndCheck: the printed settings parse as JSON and name the hook path; written into
// the fake home, check's settings lines pass; the user-owned launcher directory fails; a settings
// file without the hook fails; a missing protected file fails while an absent optional one passes.
func TestHookSettingsAndCheck(t *testing.T) {
	config := fakeHookTree(t)
	text, err := json.MarshalIndent(hook.Settings(config), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	err = json.Unmarshal(text, &parsed)
	if err != nil || !strings.Contains(string(text), `"command": "`+hook.HookPath(config)+`"`) || !strings.Contains(string(text), `"Edit(/`+config.Root+`/CLAUDE.md)"`) {
		t.Fatalf("the settings block does not parse or lacks the hook: %v\n%s", err, text)
	}
	settingsPath := config.Home + "/.claude/settings.json"
	err = os.WriteFile(settingsPath, text, 0600)
	if err != nil {
		t.Fatal(err)
	}
	report := checkReport(hook.Check(config))
	for _, wanted := range []string{"OK   settings: PreToolUse", "OK   settings: permissions.deny", "OK   settings: every sandbox", "FAIL install: " + config.LauncherDirectory + " root-owned",
		"FAIL install: " + config.LauncherDirectory + "/d1-nonet", "OK   protected: CLAUDE.md is present", "OK   protected: AGENTS.md is absent"} {
		if !strings.Contains(report, wanted) {
			t.Errorf("check did not report %q:\n%s", wanted, report)
		}
	}
	err = os.WriteFile(settingsPath, []byte(`{"sandbox":{"excludedCommands":["xcrun *","python3 *"]}}`), 0600)
	if err == nil {
		err = os.Remove(config.Root + "/containment/go/gate/gate.go")
	}
	if err != nil {
		t.Fatal(err)
	}
	report = checkReport(hook.Check(config))
	for _, wanted := range []string{"FAIL settings: PreToolUse", "FAIL settings: permissions.deny", "(not python3 *)", "FAIL protected: containment/go/gate/gate.go is missing"} {
		if !strings.Contains(report, wanted) {
			t.Errorf("check did not report %q:\n%s", wanted, report)
		}
	}
}

// checkReport prints check's lines as the binary does.
func checkReport(lines []hook.Line) string {
	var report []string
	for _, line := range lines {
		status := "OK  "
		if !line.OK {
			status = "FAIL"
		}
		report = append(report, status+" "+line.Text)
	}
	return strings.Join(report, "\n")
}
