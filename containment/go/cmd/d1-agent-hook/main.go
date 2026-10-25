// Command d1-agent-hook is a Claude Code PreToolUse hook, installed root-owned by the owner in
// /usr/local/libexec/d1-agent and named in ~/.claude/settings.json. It reads the event on stdin
// and exits 0 to let the call go on to Claude Code's own permission flow (passing the hook is not
// approval), or exits 2 with one BLOCKED line on stderr, which Claude Code shows the agent and
// which stops the call. Everything it cannot read or decide is blocked; a Go panic exits 2 too.
// The rules are in package hook. The repository root is set at build time
// (-ldflags "-X main.repositoryRoot=<root>"). No environment variable, flag or file turns it off.
//
// The owner's commands, not hook rules: "d1-agent-hook settings" prints the block for
// ~/.claude/settings.json; "d1-agent-hook check" prints one OK or FAIL line per fact the install
// rests on and exits 2 if any fails. check reports; it is not the boundary.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"d1preservation/netguard/gate"
	"d1preservation/netguard/hook"
)

// repositoryRoot is set at build time; gate.CheckRoot refuses it empty or wrong.
var repositoryRoot string

// main runs the owner's command if one is named, else decides the event on stdin.
func main() {
	signal.Ignore(syscall.SIGPIPE)
	config, configError := configuration()
	arguments := os.Args[1:]
	if len(arguments) == 1 && arguments[0] == "settings" {
		settings(config, configError)
	}
	if len(arguments) == 1 && arguments[0] == "check" {
		check(config)
	}
	if len(arguments) > 0 {
		block(fmt.Sprintf("unknown arguments %q: the hook takes none (settings and check are the owner's commands)", arguments))
	}
	if configError != nil {
		block(configError.Error())
	}
	event, err := io.ReadAll(io.LimitReader(os.Stdin, 16<<20))
	if err != nil {
		block("cannot read the event: " + err.Error())
	}
	why := hook.Decide(event, os.Getenv("CLAUDE_PROJECT_DIR"), config)
	if why != "" {
		block(why)
	}
	os.Exit(0)
}

// block prints the one BLOCKED line and exits 2, which Claude Code reads as "stop this call".
func block(why string) {
	fmt.Fprintln(os.Stderr, gate.OneLine("d1-agent-hook: BLOCKED - "+why))
	os.Exit(2)
}

// configuration is the build's repository root, the account's home directory (from the account
// database, not $HOME) and the fixed launcher directory, each checked.
func configuration() (hook.Config, error) {
	config := hook.Config{Root: repositoryRoot, LauncherDirectory: hook.LauncherDirectory}
	home, err := gate.Home()
	if err != nil {
		return config, fmt.Errorf("home directory: %w", err)
	}
	config.Home = home
	err = gate.CheckRoot(repositoryRoot)
	if err != nil {
		return config, fmt.Errorf("this hook was built without a valid repository root: %w", err)
	}
	return config, nil
}

// settings prints the settings block as indented JSON, or why it cannot, and exits.
func settings(config hook.Config, configError error) {
	if configError != nil {
		fmt.Fprintln(os.Stderr, gate.OneLine("d1-agent-hook settings: "+configError.Error()))
		os.Exit(2)
	}
	text, err := json.MarshalIndent(hook.Settings(config), "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "d1-agent-hook settings: "+err.Error())
		os.Exit(2)
	}
	fmt.Println(string(text))
	os.Exit(0)
}

// check prints every fact hook.Check measured, OK or FAIL, and exits 2 if any failed.
func check(config hook.Config) {
	failed := false
	for _, line := range hook.Check(config) {
		status := "OK  "
		if !line.OK {
			status = "FAIL"
			failed = true
		}
		fmt.Println(status + " " + gate.OneLine(line.Text))
	}
	if failed {
		os.Exit(2)
	}
	os.Exit(0)
}
