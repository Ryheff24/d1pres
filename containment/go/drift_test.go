package netguard

import (
	"regexp"
	"strings"
	"testing"
)

// sbplProfile writes game.sb's REPO parameter as one string, so the rule parser sees a literal.
func sbplProfile(profile string) string {
	parameter := regexp.MustCompile(`\(string-append \(param "REPO"\) "([^"]*)"\)`)
	return parameter.ReplaceAllString(profile, `"@REPO@$1"`)
}

// expandRules reads SBPL, without comments, into one line per rule and filter: (deny op a b)
// becomes "deny op a" and "deny op b", so a split or merged rule compares the same.
func expandRules(t *testing.T, profile string) []string {
	t.Helper()
	tokens := sbplTokens(profile)
	var rules []string
	for position := 0; position < len(tokens); {
		form, next := sbplForm(t, tokens, position)
		position = next
		if len(form) < 2 || strings.HasPrefix(form[0], "(") {
			t.Fatalf("not a rule: %v", form)
		}
		if len(form) == 2 {
			rules = append(rules, form[0]+" "+form[1])
		}
		for _, filter := range form[min(2, len(form)):] {
			rules = append(rules, form[0]+" "+form[1]+" "+filter)
		}
	}
	return rules
}

// sbplTokens splits SBPL into parentheses, strings, #"regex" literals and atoms, dropping comments.
func sbplTokens(profile string) []string {
	token := regexp.MustCompile(`;[^\n]*|#?"(?:[^"\\]|\\.)*"|[()]|[^\s()";]+`)
	var tokens []string
	for _, found := range token.FindAllString(profile, -1) {
		if !strings.HasPrefix(found, ";") {
			tokens = append(tokens, found)
		}
	}
	return tokens
}

// sbplForm reads the list starting at tokens[position] and returns its elements, nested lists
// written back as text, with the position after it.
func sbplForm(t *testing.T, tokens []string, position int) ([]string, int) {
	t.Helper()
	if tokens[position] != "(" {
		t.Fatalf("expected ( at token %d, found %q", position, tokens[position])
	}
	var elements []string
	position++
	for position < len(tokens) && tokens[position] != ")" {
		if tokens[position] != "(" {
			elements = append(elements, tokens[position])
			position++
			continue
		}
		nested, next := sbplForm(t, tokens, position)
		elements = append(elements, "("+strings.Join(nested, " ")+")")
		position = next
	}
	if position == len(tokens) {
		t.Fatal("unbalanced parentheses")
	}
	return elements, position + 1
}
