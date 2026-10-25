// Package netguard holds the reviewed profiles, embedded at build time: a launcher applies
// exactly this text wherever it is installed and whatever directory it runs from, so no file
// found at run time can select the policy (astra review 2026-10-16, finding 1).
package netguard

import _ "embed"

// GameProfile is profiles/game.sb as reviewed. Apply it through gate.Normalize.
//
//go:embed profiles/game.sb
var GameProfile string

// LocalProfile is profiles/local.sb as reviewed, d1-localonly's. Apply it through
// gate.NormalizeWith with REPO and HOME.
//
//go:embed profiles/local.sb
var LocalProfile string

// OrkeyProfile is profiles/orkey.sb as reviewed, d1-orkey's. Apply it through gate.NormalizeWith
// with SELF, the helper's own resolved path.
//
//go:embed profiles/orkey.sb
var OrkeyProfile string
