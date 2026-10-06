This directory contains the pure Go implementation from
https://github.com/FiloSottile/bigmod/tree/v0.1.0 (filippo.io/bigmod v0.1.0),
an extraction of Go 1.24's crypto/internal/fips140/bigmod.

nat.go is unchanged. The only change to nat_noasm.go is removal of its build
constraint, so the Go implementation is always selected. No assembly files
are included. Keep this directory as third-party code, rather than extending
its arithmetic for MIKE.

`storage.go` is a local adapter for caller-owned limb storage and forwards to
the existing Montgomery conversion/multiplication routines. It introduces no
arithmetic algorithms. The upstream files above remain unchanged.

Upstream file blob IDs:
- nat.go: 67f721a5e928e753838820f0ab09eb250ff0f25e
- nat_noasm.go: dbec229f5d2ece825999a3539f92bfa3e6acca42

See LICENSE for the Go Authors' BSD license.
