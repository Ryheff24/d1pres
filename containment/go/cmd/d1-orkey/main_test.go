package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"d1preservation/netguard/orkey"
)

// handoffKey stands in for the owner's key; it passes orkey.CheckKey.
const handoffKey = "sk-or-v1-handoff0123456789"

// roleVariable makes this test binary play one side of the key hand-off: "launcher" hands the key
// over with handKey and execs this binary again as "server", which reads it the way serve does.
// The exec is a real one, as in launch; only sandbox-exec is left out (the agent hook refuses it
// to agents, so the owner's first start is the check of that last step).
const roleVariable = "D1_ORKEY_TEST_ROLE"

func TestMain(m *testing.M) {
	switch os.Getenv(roleVariable) {
	case "launcher", "launcher-cloexec":
		_, _, free := syscall.Syscall(syscall.SYS_FCNTL, orkey.KeyDescriptor, syscall.F_GETFD, 0)
		if err := handKey(handoffKey); err != nil {
			fmt.Println("handKey:", err)
			os.Exit(3)
		}
		if os.Getenv(roleVariable) == "launcher-cloexec" {
			// The sabotaged twin: the flag the 21:15 start left set.
			syscall.Syscall(syscall.SYS_FCNTL, orkey.KeyDescriptor, syscall.F_SETFD, syscall.FD_CLOEXEC)
		}
		fmt.Printf("launcher: descriptor %d was free before the pipe: %t\n", orkey.KeyDescriptor, free == syscall.EBADF)
		self, _ := os.Executable()
		environment := append(withoutRole(os.Environ()), roleVariable+"=server")
		err := syscall.Exec(self, []string{self, "-test.run=^$"}, environment)
		fmt.Println("exec:", err)
		os.Exit(3)
	case "server":
		key, err := orkey.ReadKey(os.NewFile(orkey.KeyDescriptor, "key"))
		if err != nil {
			fmt.Println("server:", err)
			os.Exit(4)
		}
		if key != handoffKey {
			fmt.Println("server: a different key arrived")
			os.Exit(4)
		}
		fmt.Println("server: key received")
		os.Exit(0)
	case "read-secret":
		key, err := readSecret()
		fmt.Printf("read-secret: %d bytes, %v\n", len(key), err)
		os.Exit(0)
	case "store-key":
		storeKey()
	}
	os.Exit(m.Run())
}

// withoutRole drops roleVariable: Getenv reads the first of two entries, so an appended role
// would not replace the old one and the server would hand off again, forever (seen 21:2x).
func withoutRole(environment []string) []string {
	var kept []string
	for _, variable := range environment {
		if !strings.HasPrefix(variable, roleVariable+"=") {
			kept = append(kept, variable)
		}
	}
	return kept
}

// handOff runs this binary as the launcher in role and returns its output and error. The child's
// stdin is a pipe holding handoffKey, never the terminal, so a test cannot wait on the owner.
func handOff(t *testing.T, role string) (string, error) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, self, "-test.run=^$")
	child.Env = append(withoutRole(os.Environ()), roleVariable+"="+role)
	child.Stdin = strings.NewReader(handoffKey + "\n")
	output, err := child.CombinedOutput()
	return string(output), err
}

// TestReadSecretRefusesPipe: a key offered on a pipe is not read; only a terminal is.
func TestReadSecretRefusesPipe(t *testing.T) {
	output, err := handOff(t, "read-secret")
	if err != nil || !strings.Contains(output, "read-secret: 0 bytes, stdin is not a terminal") {
		t.Fatalf("a pipe on stdin was not refused (%v):\n%s", err, output)
	}
}

// TestStoreKeyOnlyInstalled: store-key from any binary but the installed one refuses before it
// reads anything or touches the Keychain, since the item would trust that binary.
func TestStoreKeyOnlyInstalled(t *testing.T) {
	output, err := handOff(t, "store-key")
	if err == nil || !strings.Contains(output, "KEY NOT STORED - run it as "+installedPath) || strings.Contains(output, "OpenRouter key") {
		t.Fatalf("store-key from a test binary was not refused first (%v):\n%s", err, output)
	}
}

// TestKeyCrossesExec: the key handed over by handKey is read by the exec'd server.
func TestKeyCrossesExec(t *testing.T) {
	output, err := handOff(t, "launcher")
	if err != nil || !strings.Contains(output, "server: key received") {
		t.Fatalf("the key did not cross the exec (%v):\n%s", err, output)
	}
	if strings.Contains(output, handoffKey) {
		t.Fatal("the key appeared in the output")
	}
	// The 21:15 failure needs the pipe's read end to land at descriptor 3, where dup2 copies
	// nothing; a launcher with descriptor 3 already taken would not exercise it.
	if !strings.Contains(output, "was free before the pipe: true") {
		t.Fatalf("descriptor 3 was taken in the launcher, so the failing case was not exercised:\n%s", output)
	}
	t.Log(strings.TrimSpace(output))
}

// TestKeyFromEnvironmentFirst: with OPENROUTER_API_KEY set (op run), that is the key, and it is
// gone from the process and from the environment handed on, whatever the Keychain holds.
func TestKeyFromEnvironmentFirst(t *testing.T) {
	t.Setenv(orkey.KeyVariable, handoffKey)
	key, environment, err := takeKey(os.Environ())
	if err != nil || key != handoffKey {
		t.Fatalf("the environment key was not taken (%v)", err)
	}
	_, still := os.LookupEnv(orkey.KeyVariable)
	if still || strings.Contains(strings.Join(environment, "\n"), handoffKey) {
		t.Fatal("the key stayed in the environment")
	}
}

// TestKeychainMissingItem: a Keychain item that does not exist is a refusal that names the store
// command, not an empty key; the positive case is the owner's first start (README).
func TestKeychainMissingItem(t *testing.T) {
	key, err := keychainKey("d1-orkey-test-absent", "none")
	if err == nil || key != "" || !strings.Contains(err.Error(), "no Keychain item") {
		t.Fatalf("an absent item gave key %q, error %v", key, err)
	}
}

// TestKeyCrossesExecCatchesCloseOnExec: the same hand-off with close-on-exec set must fail as the
// owner's first start did ("bad file descriptor"), so a pass above is not a test that cannot fail.
func TestKeyCrossesExecCatchesCloseOnExec(t *testing.T) {
	output, err := handOff(t, "launcher-cloexec")
	if err == nil || !strings.Contains(output, "bad file descriptor") {
		t.Fatalf("close-on-exec did not break the hand-off (%v):\n%s", err, output)
	}
}
