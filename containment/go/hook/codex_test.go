package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCodexRequirements: the requirements make d1 the default, allow only :read-only and d1, extend
// :workspace, and give every protected file and tree a "read" line; each line is a comment, a table,
// a blank or one key = value; a root a TOML key would need escaping for is refused.
func TestCodexRequirements(t *testing.T) {
	config := Config{Root: "/Users/owner/d1preservation", Home: "/Users/owner"}
	text, err := CodexRequirements(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"default_permissions = \"d1\"\n", "\n[allowed_permission_profiles]\n\":read-only\" = true\nd1 = true\n\n", "[permissions.d1]\n", "extends = \":workspace\"\n", "[permissions.d1.filesystem]\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("the requirements lack %q:\n%s", want, text)
		}
	}
	paths := append(ProtectedPaths(config), ProtectedTreePaths(config)...)
	if len(paths) < 10 {
		t.Fatalf("only %d protected paths", len(paths))
	}
	for _, path := range paths {
		if !strings.Contains(text, "\n\""+path+"\" = \"read\"\n") {
			t.Errorf("the requirements do not keep %s read-only", path)
		}
	}
	for _, refused := range []string{"danger", "\":workspace\" = true", "= \"write\"", "= \"deny\""} {
		if strings.Contains(text, refused) {
			t.Errorf("the requirements hold %q", refused)
		}
	}
	for number, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		table := strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]")
		if line != "" && !strings.HasPrefix(line, "# ") && !table && strings.Count(line, " = ") != 1 {
			t.Errorf("line %d is not one TOML entry: %q", number+1, line)
		}
	}
	for _, root := range []string{"/Users/owner/d1\"x", "/Users/owner/d1\\x", "/Users/owner/d1\nx", "relative/d1"} {
		if _, err := CodexRequirements(Config{Root: root, Home: "/Users/owner"}); err == nil {
			t.Errorf("a root of %q was written into the requirements", root)
		}
	}
}

// TestCheckCodex: the requirements line fails when the file is missing, differs or is not
// root-owned (a file the test writes never is), and the user-config line fails on each older
// sandbox setting and passes without one.
func TestCheckCodex(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Root: filepath.Join(base, "repo"), Home: filepath.Join(base, "home")}
	wanted, err := CodexRequirements(config)
	if err != nil {
		t.Fatal(err)
	}
	saved := codexRequirementsPath
	t.Cleanup(func() { codexRequirementsPath = saved })
	codexRequirementsPath = filepath.Join(base, "requirements.toml")
	if err := os.MkdirAll(filepath.Join(config.Home, ".codex"), 0o755); err != nil {
		t.Fatal(err)
	}
	userConfig := filepath.Join(config.Home, ".codex", "config.toml")
	cases := []struct {
		name, requirements, user string
		requirementsOK, userOK   bool
		why                      string
	}{
		{"missing", "", "model = \"x\"\n", false, true, "no such file"},
		{"differs", wanted + "d1x = true\n", "model = \"x\"\n", false, true, "differs"},
		{"same, user-owned", wanted, "model = \"x\"\n", false, true, "must be root-owned"},
		{"sandbox_mode", wanted, "model = \"x\"\n  sandbox_mode = \"workspace-write\"\n", false, false, "must be root-owned"},
		{"sandbox table", wanted, "[sandbox_workspace_write]\nnetwork_access = false\n", false, false, "must be root-owned"},
	}
	for _, test := range cases {
		os.Remove(codexRequirementsPath)
		if test.requirements != "" {
			if err := os.WriteFile(codexRequirementsPath, []byte(test.requirements), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(userConfig, []byte(test.user), 0o644); err != nil {
			t.Fatal(err)
		}
		lines := checkCodex(config)
		if len(lines) != 2 || lines[0].OK != test.requirementsOK || lines[1].OK != test.userOK || !strings.Contains(lines[0].Text, test.why) {
			t.Errorf("%s: got %+v", test.name, lines)
		}
		if !test.userOK && !strings.Contains(lines[1].Text, "(remove ") {
			t.Errorf("%s: the user-config line does not name the setting: %s", test.name, lines[1].Text)
		}
	}
	reported := 0
	for _, line := range Check(config) {
		if strings.HasPrefix(line.Text, "codex: ") {
			reported++
		}
	}
	if reported != 2 {
		t.Errorf("Check reports %d codex lines, not 2", reported)
	}
}
