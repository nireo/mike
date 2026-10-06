package mike

import (
	"bytes"
	"crypto/subtle"
	"runtime"
	"testing"
	"time"
)

// BenchmarkParameterSets measures the public API, including allocation, scalar
// validation, peer verification, encoding, and hashing. GenerateKey also includes
// fresh crypto/rand entropy. Input decoding and reference checks are setup work.
func BenchmarkParameterSets(b *testing.B) {
	benchmarkParameterSets(b, false)
}

// BenchmarkParameterSetsDIT additionally enters the stdlib's architectural
// timing mode for each API call. This measures a candidate mitigation from the
// timing review; the production API does not yet enable this mode itself.
func BenchmarkParameterSetsDIT(b *testing.B) {
	benchmarkParameterSets(b, true)
}

func benchmarkParameterSets(b *testing.B, dit bool) {
	for _, set := range parameterSets {
		b.Run(set.String(), func(b *testing.B) {
			b.Run("GenerateKey", func(b *testing.B) {
				benchmarkOperation(b, dit, func() error {
					public, secret, err := set.GenerateKey(nil)
					runtime.KeepAlive(public)
					runtime.KeepAlive(secret)
					return err
				})
			})
			b.Run("Exchange", func(b *testing.B) {
				vectors := readParameterVectors(b, set)
				type input struct{ public, secret []byte }
				inputs := make([]input, len(vectors.Exchanges))
				for i, v := range vectors.Exchanges {
					inputs[i] = input{
						decodeHex(b, vectors.Keypairs[v.Bob].PublicKey),
						decodeHex(b, vectors.Keypairs[v.Alice].SecretKey),
					}
					shared, err := set.Exchange(inputs[i].public, inputs[i].secret)
					if err != nil || !bytes.Equal(shared[:], decodeHex(b, v.SharedSecret)) {
						b.Fatalf("reference exchange %d: mismatch or error: %v", i, err)
					}
				}
				i := 0
				benchmarkOperation(b, dit, func() error {
					in := inputs[i]
					i = (i + 1) % len(inputs)
					shared, err := set.Exchange(in.public, in.secret)
					runtime.KeepAlive(shared)
					return err
				})
			})
		})
	}
}

func benchmarkOperation(b *testing.B, dit bool, operation func() error) {
	b.Helper()
	b.ReportAllocs()
	for b.Loop() {
		var err error
		if dit {
			subtle.WithDataIndependentTiming(func() { err = operation() })
		} else {
			err = operation()
		}
		if err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.Elapsed())/float64(b.N)/float64(time.Millisecond), "ms/op")
}
