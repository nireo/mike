# mike: Module Isogeny Key-Exchange

A port of `mike_c`, implementing **key generation and exchange for all six
parameter sets**. It keeps the C formulas and isogeny
strategy recognizable while using ordinary Go types, errors, and `io.Reader`.

Implemented:

- Secret sampling and deterministic public-key derivation.
- The three-point Montgomery ladder and degree-4 isogeny chain.
- Montgomery curve normalization.
- C-compatible secret/public key encodings and canonical public-key parsing.
- Deterministic torsion-basis generation and Jacobian point operations.
- Scholten, diagonal, and Weil gluing, followed by the four-dimensional isogeny chain.
- Shared invariants and SHA3-256 shared-secret derivation.

The package-level functions use `p308_633`. Select another set with
`ParameterSet` methods; each uses the same protocol formulas with its own
modulus, basis, scalar length, cofactor, and isogeny-chain lengths.
`HashSharedSecret` is also available for hashing separately supplied invariants.

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

These methods return keys as byte slices and shared secrets as `[32]byte`.
They provide `PublicKeyFromSecretKey`, `ParseSecretKey`, `ParsePublicKey`, and
`HashSharedSecret`, with the same checks as the default API. Parsers return
independent copies. Invalid `ParameterSet` values return `ErrParameterSet`.
Each set's context is immutable, so different sets can be used concurrently.
Keys carry no parameter-set tag; both parties must select the same set.

The security levels below are the C reference's nominal `SECURITY_BITS` values.
Key and field sizes are in bytes; shared secrets are 32 bytes for every set.

| ParameterSet | Security bits | Secret key | Public key | Field element |
| --- | ---: | ---: | ---: | ---: |
| `P308_633` | 128 | 29 | 80 | 40 |
| `P374_117` | 128 | 47 | 96 | 48 |
| `P474_593` | 192 | 43 | 122 | 61 |
| `P566_77` | 192 | 71 | 144 | 72 |
| `P628_317` | 256 | 57 | 160 | 80 |
| `P758_41` | 256 | 95 | 192 | 96 |

Call `set.SecurityBits()`, `set.SecretKeySize()`, `set.PublicKeySize()`, or
`set.FieldElementSize()` to obtain these values. `set.String()` returns its C name.

The default `SecretKey` and `PublicKey` are fixed-size byte arrays (29 and 80 bytes).
`ParseSecretKey` checks the scalar constraints enforced by C key generation;
the C secret decoder itself does not check these constraints.
`ParsePublicKey` checks canonical field encodings, matching the C decoder. It
does not validate supersingularity or curve membership.

`Exchange(peerPublic, ourSecret)` returns a 32-byte array. It checks the scalar
and canonical public-key encoding, verifies the public curve through the
protocol's torsion/gluing checks, and rejects all-zero invariants. Failures
return an error and a zero result. Basis searches depend only on the public
curve and are capped at 256 candidates, so malformed keys cannot cause an
unbounded search. Secret-dependent selection uses the standard library's
`crypto/subtle` primitives.

Prime-field arithmetic uses the locally included pure Go implementation of
[`filippo.io/bigmod` v0.1.0](https://github.com/FiloSottile/bigmod/tree/v0.1.0),
an extraction of Go's `crypto/internal/fips140/bigmod`. Its arithmetic is kept
unchanged; the assembly files are omitted and the Go backend is always enabled.
See [the provenance note](internal/bigmod/README.md). `math/big` is used only
during initialization of public moduli and fixed exponents. The small Fp2
wrappers follow the C formulas and delegate modular arithmetic to bigmod. Randomness,
SHA3-256, and conditional selection use the standard library. There are no
external module dependencies, cgo, or assembly files in the Go implementation.

The main source mapping is:

| Go | C reference |
| --- | --- |
| `mike.go`, `parameter_set.go` | `nike/ref/lvlx/keygen.c`, `encode.c` |
| `fp.go` | wrappers around bigmod; Fp2 formulas from `gf/ref/lvlx/fp2.c` |
| `ec.go` | key-generation functions in `ec/ref/lvlx/ec.c`, `isog_chains.c` |
| `normalize.go` | `ec/ref/lvlx/normalize.c` |
| `params.go`, `params_generated.go` | public moduli and canonical basis values from all six `precomp/ref` sets |
| `exchange.go` | `nike/ref/lvlx/exchange.c`, `weil/ref/lvlx/mike_dim4_chain.c` |
| `ec_jacobian.go`, `basis.go` | exchange operations in `ec/ref/lvlx/ec.c`, `basis.c`, and `weil/ref/lvlx/bases.c` |
| `fp_exchange.go` | square-root and projective-inversion formulas from `gf/ref/lvlx` |
| `theta.go` | `theta/ref/include/theta.h` and `theta/ref/lvlx` |
| `gluing.go`, `invariants.go` | `weil/ref/lvlx/gluing.c`, `invariants.c` |

Run the simple tests and benchmark with Go 1.27:

```sh
go test ./...
go test -race ./...
go test -run '^$' -bench . -benchmem
```

Tests include eight key-pair vectors and six exchange vectors **for each set**,
generated by the C reference, checking raw invariants and final shared secrets
in both directions. They also cover fresh-key agreement for all sets, concurrent
use of different sets, mixed-set key rejection, scalar sampling boundaries,
invalid encodings and curves, partial/failing random readers, field checks
against `math/big` for every modulus, and the C shared-invariant hash. Normal
tests require only Go and also run the fuzz seed corpora as regression tests.

Five native Go fuzz targets cover all six parameter sets:

- `FuzzParseSecretKey`: scalar constraints, invalid sets, and independent copies.
- `FuzzParsePublicKey`: canonical encoding checked against an integer oracle.
- `FuzzHashSharedSecret`: invariant encoding, hashing, and zero results on error.
- `FuzzExchange`: arbitrary peer encodings with a valid fixed secret, including
  ordinary and non-normalized curves, input preservation, and zero results on error.
- `FuzzKeyExchangeAgreement`: key generation, public-key derivation, and agreement
  from mutated entropy, with C vector comparisons whenever a reference seed or
  key pair is reproduced.

The corpora include C vectors, zero and maximal scalars, field boundaries,
incorrect lengths, and invalid parameter-set values. The agreement target pads
or truncates entropy to the selected key size so mutations keep reaching valid
exchanges. The exchange target keeps the secret valid so mutations reach peer
validation. Fuzz tests use committed fixtures and require no C compiler.

Run one target at a time; for example:

```sh
go test -run '^$' -fuzz '^FuzzExchange$' -fuzztime 30s -parallel 2 -timeout 5m
go test -run '^$' -fuzz '^FuzzKeyExchangeAgreement$' -fuzztime 30s -parallel 2 -timeout 5m
```

Replace the target name to run the parser or hash targets. Exchange targets are
substantially more expensive, so keep worker counts small. Go saves failing
inputs under `testdata/fuzz/<target>`; keep those files as regression cases.
Longer fuzz campaigns can use `-fuzztime 10m` with a suitably larger `-timeout`.

To regenerate the vectors from the checked-in C source (Python 3 and clang):

```sh
python3 testdata/generate_vectors.py
gofmt -w params_generated.go
```

The generator corrects the C ladder's mismatched `void` return type to `int`
in a temporary copy, consistent with its header and return statements. It
does not modify `mike_c`. The constants are converted from the C Montgomery
representation with the reference's own `fp_encode`.

The MIKE port is Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
The included bigmod implementation has its own [BSD license](internal/bigmod/LICENSE).
