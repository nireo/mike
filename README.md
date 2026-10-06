# mike: Module Isogeny Key-Exchange

Pure Go key generation and exchange for all six MIKE parameter sets, with
C-compatible encodings and formulas that follow `mike_c`. Requires Go 1.27.

```go
package main

import (
    "fmt"
    "log"

    "github.com/nireo/mike"
)

func main() {
    set := mike.P628_317 // Choose the same set for both parties.
    alicePublic, aliceSecret, err := set.GenerateKey(nil) // crypto/rand.Reader
    if err != nil {
        log.Fatal(err)
    }
    bobPublic, bobSecret, err := set.GenerateKey(nil)
    if err != nil {
        log.Fatal(err)
    }
    aliceShared, err := set.Exchange(bobPublic, aliceSecret)
    if err != nil {
        log.Fatal(err)
    }
    bobShared, err := set.Exchange(alicePublic, bobSecret)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(aliceShared == bobShared) // true
}
```

Use the same parameter set for both parties. `ParameterSet` methods return keys
as byte slices and shared secrets as `[32]byte`; keys carry no set identifier.
The package-level API defaults to `P308_633` and uses fixed-size key arrays.
A nil randomness reader uses `crypto/rand.Reader`.

Also available: `PublicKeyFromSecretKey`, `ParseSecretKey`, `ParsePublicKey`,
and `HashSharedSecret`. Parsers return independent copies. Public-key parsing
checks canonical encoding; `Exchange` performs the protocol's curve/gluing
checks and returns a zero shared secret on error.

Sizes are in bytes. Security levels are the C reference's nominal values;
shared secrets are 32 bytes for every set.

| ParameterSet | Security bits | Secret key | Public key | Field element |
| --- | ---: | ---: | ---: | ---: |
| `P308_633` | 128 | 29 | 80 | 40 |
| `P374_117` | 128 | 47 | 96 | 48 |
| `P474_593` | 192 | 43 | 122 | 61 |
| `P566_77` | 192 | 71 | 144 | 72 |
| `P628_317` | 256 | 57 | 160 | 80 |
| `P758_41` | 256 | 95 | 192 | 96 |

Fields use vendored pure Go [bigmod](internal/bigmod/README.md). `math/big` is
used only to initialize public parameters; randomness, SHA3-256, and conditional
selection use the standard library. No cgo, assembly, or external module dependencies.
Field temporaries use fixed-size stack storage and remain in Montgomery form
between multiplications.

See the [timing review](TIMING_REVIEW.md) for findings and remaining timing risks.

Tests cover C vectors for every set, agreement, invalid keys, field arithmetic,
and fuzz seed corpora. Run tests, benchmarks, or one fuzz target at a time:

```sh
go test ./...
go test -race ./...
go test -run '^$' -bench '^BenchmarkParameterSets(DIT)?$' -benchmem -cpu 1 -count 3
go test -run '^$' -fuzz '^FuzzExchange$' -fuzztime 30s -parallel 2 -timeout 5m
```

Benchmarks cover all sets; see the [performance comparison](benchmarks/README.md)
for methodology and results against the published C timings.

The five [fuzz targets](fuzz_test.go) cover secret/public key parsing, invariant
hashing, malformed peers, and generated-key agreement. Normal tests need only
Go. Keep failing inputs saved under `testdata/fuzz/` as regression cases.

Regenerate fixtures and constants using a local `mike_c` checkout, Python 3,
and clang:

```sh
python3 testdata/generate_vectors.py
gofmt -w params_generated.go
```
