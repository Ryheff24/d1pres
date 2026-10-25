package netguard

import (
	"os"
	"strconv"
	"testing"

	"d1preservation/netguard/gate"
)

// TestWriteExclusions: under game.sb, create, write, rename and unlink of a .sb file and of a
// file in a /private/tmp/claude* directory are each refused, though /private/tmp is writable;
// with that one exclusion removed from the policy, the same attempts succeed.
func TestWriteExclusions(t *testing.T) {
	requireWriteExclusions(t, GameProfile, func(profile string) string {
		return gate.Normalize(profile, repositoryRoot)
	})
}

// TestLocalWriteExclusions: the same two exclusions in local.sb, normalized as d1-localonly does
// (REPO this repository, HOME the account's home), with the same removed-rule positive control.
func TestLocalWriteExclusions(t *testing.T) {
	requireWriteExclusions(t, LocalProfile, func(profile string) string {
		return localPolicy(t, profile, repositoryRoot)
	})
}

// requireWriteExclusions runs the mutate probe for the .sb and /private/tmp/claude exclusions
// under profile (normalized by normalize): refused with the rule, allowed with it removed.
func requireWriteExclusions(t *testing.T, profile string, normalize func(string) string) {
	t.Helper()
	requireSeatbelt(t)
	identifier := strconv.Itoa(os.Getpid())
	claudeDirectory := "/private/tmp/claude-" + strconv.Itoa(os.Getuid()) + "-test-" + identifier
	err := os.Mkdir(claudeDirectory, 0700)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.RemoveAll(claudeDirectory)
	})
	sbPrefix := "/private/tmp/d1-nonet-test-" + identifier
	cases := []struct {
		name      string
		exclusion string
		paths     []string // new, existing, renamed
	}{
		{"sb", `(regex #"\.sb$")`, []string{sbPrefix + ".sb", sbPrefix + "-existing.sb", sbPrefix + "-renamed.txt"}},
		{"claude", `(regex #"^/private/tmp/claude")`, []string{claudeDirectory + "/new", claudeDirectory + "/existing", claudeDirectory + "/renamed"}},
	}
	for _, exclusion := range cases {
		t.Run(exclusion.name, func(t *testing.T) {
			t.Cleanup(func() {
				for _, path := range exclusion.paths {
					os.Remove(path)
				}
			})
			policy := normalize(profile)
			writeFixture(t, exclusion.paths[1])
			requirePolicyProbe(t, policy, append([]string{"mutate", "denied"}, exclusion.paths...)...)
			broken := normalize(removeLines(t, profile, containing(exclusion.exclusion)))
			writeFixture(t, exclusion.paths[1])
			requirePolicyProbe(t, broken, append([]string{"mutate", "allowed"}, exclusion.paths...)...)
		})
	}
}

// writeFixture creates the existing file a mutate probe writes, renames and unlinks.
func writeFixture(t *testing.T, path string) {
	t.Helper()
	err := os.WriteFile(path, []byte("fixture\n"), 0600)
	if err != nil {
		t.Fatal(err)
	}
}
