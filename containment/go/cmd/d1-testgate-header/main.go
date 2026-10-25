// Command d1-testgate-header prints the C header the test gate is compiled with: the repository
// root and the game profile, normalized exactly as d1-nonet applies it, so the gate's apply stacks
// on the launcher's. install.sh runs it: go run ./cmd/d1-testgate-header ROOT > header.
package main

import (
	"fmt"
	"os"
	"strconv"

	"d1preservation/netguard"
	"d1preservation/netguard/gate"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: d1-testgate-header ROOT")
		os.Exit(64)
	}
	root := os.Args[1]
	err := gate.CheckRoot(root)
	if err != nil {
		refuse("root: " + err.Error())
	}
	policy := gate.Normalize(netguard.GameProfile, root)
	// strconv.Quote writes a C string literal only for printable ASCII; anything else is refused.
	for _, text := range []string{root, policy} {
		for _, character := range text {
			if character < 0x20 || character > 0x7e {
				refuse(fmt.Sprintf("%q holds a character a C string literal would need escaping for", text))
			}
		}
	}
	fmt.Printf("#define D1_REPO %s\n#define D1_NETGATE_PROFILE %s\n", strconv.Quote(root), strconv.Quote(policy))
}

// refuse prints one line and exits 2.
func refuse(why string) {
	fmt.Fprintln(os.Stderr, gate.OneLine("d1-testgate-header: "+why))
	os.Exit(2)
}
