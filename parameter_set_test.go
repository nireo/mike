package mike

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"
	"testing/iotest"
)

var parameterSets = []ParameterSet{P308_633, P374_117, P474_593, P566_77, P628_317, P758_41}

func TestParameterSetSizes(t *testing.T) {
	for _, tc := range []struct {
		set                             ParameterSet
		name                            string
		security, secret, public, field int
	}{
		{P308_633, "p308_633", 128, 29, 80, 40},
		{P374_117, "p374_117", 128, 47, 96, 48},
		{P474_593, "p474_593", 192, 43, 122, 61},
		{P566_77, "p566_77", 192, 71, 144, 72},
		{P628_317, "p628_317", 256, 57, 160, 80},
		{P758_41, "p758_41", 256, 95, 192, 96},
	} {
		if tc.set.String() != tc.name || tc.set.SecurityBits() != tc.security ||
			tc.set.SecretKeySize() != tc.secret || tc.set.PublicKeySize() != tc.public || tc.set.FieldElementSize() != tc.field {
			t.Errorf("incorrect metadata for %s", tc.name)
		}
	}
}

// Concurrent set subtests also exercise isolation of moduli and constants.
func TestAllParameterReferenceVectors(t *testing.T) {
	for _, set := range parameterSets {
		t.Run(set.String(), func(t *testing.T) {
			t.Parallel()
			v := readParameterVectors(t, set)
			f, err := set.parameters()
			if err != nil {
				t.Fatal(err)
			}
			for i, vector := range v.Keypairs {
				t.Run(fmt.Sprintf("keypair-%d", i), func(t *testing.T) {
					seed := bytes.NewReader(decodeHex(t, vector.Seed))
					public, secret, err := set.GenerateKey(iotest.HalfReader(seed))
					if err != nil {
						t.Fatal(err)
					}
					if hex.EncodeToString(public) != vector.PublicKey || hex.EncodeToString(secret) != vector.SecretKey {
						t.Fatal("key pair differs from C")
					}
					if seed.Len() != 0 {
						t.Fatal("incorrect randomness consumption")
					}
					parsedSecret, err := set.ParseSecretKey(secret)
					if err != nil || !bytes.Equal(parsedSecret, secret) {
						t.Fatalf("parse scalar: %v", err)
					}
					parsedPublic, err := set.ParsePublicKey(public)
					if err != nil || !bytes.Equal(parsedPublic, public) {
						t.Fatalf("parse public key: %v", err)
					}
					derived, err := set.PublicKeyFromSecretKey(parsedSecret)
					if err != nil || !bytes.Equal(derived, public) {
						t.Fatalf("derive public key: %v", err)
					}
					secret[1] ^= 1
					public[0] ^= 1
					if parsedSecret[1] == secret[1] || parsedPublic[0] == public[0] {
						t.Fatal("parser aliases its input")
					}
				})
			}
			for _, vector := range v.Exchanges {
				t.Run(fmt.Sprintf("exchange-%d-%d", vector.Alice, vector.Bob), func(t *testing.T) {
					alice := v.Keypairs[vector.Alice]
					bob := v.Keypairs[vector.Bob]
					alicePublic, aliceSecret := decodeHex(t, alice.PublicKey), decodeHex(t, alice.SecretKey)
					bobPublic, bobSecret := decodeHex(t, bob.PublicKey), decodeHex(t, bob.SecretKey)
					invariants := make([]byte, 4*f.fieldBytes)
					err := f.exchangeInvariants(invariants, bobPublic, aliceSecret)
					if err != nil || hex.EncodeToString(invariants) != vector.Invariants {
						t.Fatalf("C invariants mismatch: %v", err)
					}
					a, err := set.Exchange(bobPublic, aliceSecret)
					if err != nil {
						t.Fatal(err)
					}
					b, err := set.Exchange(alicePublic, bobSecret)
					if err != nil {
						t.Fatal(err)
					}
					if a != b || hex.EncodeToString(a[:]) != vector.SharedSecret {
						t.Fatal("C shared secret mismatch")
					}
					hashed, err := set.HashSharedSecret(invariants)
					if err != nil || hashed != a {
						t.Fatalf("invariant hash: %v", err)
					}
				})
			}
			hash, err := set.HashSharedSecret(decodeHex(t, v.Invariants))
			if err != nil || hex.EncodeToString(hash[:]) != v.SharedHash {
				t.Fatalf("C invariant hash mismatch: %v", err)
			}
		})
	}
}

func TestAllParameterGeneratedAgreement(t *testing.T) {
	for _, set := range parameterSets {
		t.Run(set.String(), func(t *testing.T) {
			t.Parallel()
			alicePublic, aliceSecret, err := set.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			bobPublic, bobSecret, err := set.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			a, err := set.Exchange(bobPublic, aliceSecret)
			if err != nil {
				t.Fatal(err)
			}
			b, err := set.Exchange(alicePublic, bobSecret)
			if err != nil || a != b || a == ([SharedSecretSize]byte{}) {
				t.Fatalf("fresh agreement: %v", err)
			}
		})
	}
}

func TestAllParameterValidation(t *testing.T) {
	for _, set := range parameterSets {
		t.Run(set.String(), func(t *testing.T) {
			v := readParameterVectors(t, set)
			public := decodeHex(t, v.Keypairs[0].PublicKey)
			secret := decodeHex(t, v.Keypairs[0].SecretKey)
			for _, length := range []int{0, set.SecretKeySize() - 1, set.SecretKeySize() + 1} {
				bad := make([]byte, length)
				if _, err := set.ParseSecretKey(bad); !errors.Is(err, ErrSecretKey) {
					t.Fatal("accepted scalar length")
				}
				if _, err := set.PublicKeyFromSecretKey(bad); !errors.Is(err, ErrSecretKey) {
					t.Fatal("derived scalar length")
				}
				checkExchangeError(t, set, public, bad, ErrSecretKey)
			}
			for bit := 0; bit < 8; bit++ {
				if bit == 3 {
					continue
				}
				bad := slices.Clone(secret)
				bad[0] = bad[0]&^7 | byte(bit)
				if _, err := set.ParseSecretKey(bad); !errors.Is(err, ErrSecretKey) {
					t.Fatal("accepted low bits")
				}
				if _, err := set.PublicKeyFromSecretKey(bad); !errors.Is(err, ErrSecretKey) {
					t.Fatal("derived invalid low bits")
				}
				checkExchangeError(t, set, public, bad, ErrSecretKey)
			}
			for bit := 4; bit < 8; bit++ {
				bad := slices.Clone(secret)
				bad[len(bad)-1] |= 1 << bit
				if _, err := set.ParseSecretKey(bad); !errors.Is(err, ErrSecretKey) {
					t.Fatal("accepted high bits")
				}
				if _, err := set.PublicKeyFromSecretKey(bad); !errors.Is(err, ErrSecretKey) {
					t.Fatal("derived invalid high bits")
				}
				checkExchangeError(t, set, public, bad, ErrSecretKey)
			}
			for _, length := range []int{0, set.PublicKeySize() - 1, set.PublicKeySize() + 1} {
				bad := make([]byte, length)
				if _, err := set.ParsePublicKey(bad); !errors.Is(err, ErrPublicKey) {
					t.Fatal("accepted public key length")
				}
				checkExchangeError(t, set, bad, secret, ErrPublicKey)
			}
			f, _ := set.parameters()
			p := slices.Clone(f.primeBytes)
			slices.Reverse(p)
			for _, bad := range [][]byte{p, bytes.Repeat([]byte{0xff}, set.FieldElementSize())} {
				for i := 0; i < 2; i++ {
					encoded := slices.Clone(public)
					copy(encoded[i*f.fieldBytes:], bad)
					if _, err := set.ParsePublicKey(encoded); !errors.Is(err, ErrPublicKey) {
						t.Fatal("accepted noncanonical component")
					}
					checkExchangeError(t, set, encoded, secret, ErrPublicKey)
				}
				for i := 0; i < 4; i++ {
					encoded := make([]byte, 4*f.fieldBytes)
					copy(encoded[i*f.fieldBytes:], bad)
					result, err := set.HashSharedSecret(encoded)
					if !errors.Is(err, ErrInvariants) || result != ([SharedSecretSize]byte{}) {
						t.Fatal("accepted noncanonical invariant")
					}
				}
			}
			for _, length := range []int{0, 4*f.fieldBytes - 1, 4*f.fieldBytes + 1} {
				result, err := set.HashSharedSecret(make([]byte, length))
				if !errors.Is(err, ErrInvariants) || result != ([SharedSecretSize]byte{}) {
					t.Fatal("accepted invariant length")
				}
			}
			boundary := make([]byte, f.publicBytes)
			copy(boundary, p)
			boundary[0]-- // p-1 and zero are canonical.
			if _, err := set.ParsePublicKey(boundary); err != nil {
				t.Fatal(err)
			}
			for _, curve := range []fp2{f.fp2Small(0), f.fp2Small(2), {f.fpSmall(1), f.fpSmall(1)}} {
				encoded := make([]byte, f.publicBytes)
				f.fp2Encode(encoded, curve)
				checkExchangeError(t, set, encoded, secret, ErrExchange)
			}
			curve, _ := f.decodePublicKey(public)
			for _, curve := range []fp2{f.fp2Neg(curve), f.fp2Frob(curve)} {
				encoded := make([]byte, f.publicBytes)
				f.fp2Encode(encoded, curve)
				checkExchangeError(t, set, encoded, secret, ErrExchange)
			}
			for _, other := range parameterSets {
				if other == set {
					continue
				}
				otherKeys := readParameterVectors(t, other).Keypairs[0]
				checkExchangeError(t, set, decodeHex(t, otherKeys.PublicKey), secret, ErrPublicKey)
				checkExchangeError(t, set, public, decodeHex(t, otherKeys.SecretKey), ErrSecretKey)
			}
			for _, tc := range []struct {
				reader io.Reader
				err    error
			}{
				{bytes.NewReader(nil), io.EOF},
				{bytes.NewReader(make([]byte, f.secretBytes-1)), io.ErrUnexpectedEOF},
				{iotest.ErrReader(io.ErrClosedPipe), io.ErrClosedPipe},
			} {
				pk, sk, err := set.GenerateKey(tc.reader)
				if !errors.Is(err, tc.err) || pk != nil || sk != nil {
					t.Fatalf("partial keys on randomness failure: %v", err)
				}
			}
		})
	}
}

func checkExchangeError(t *testing.T, set ParameterSet, public, secret []byte, want error) {
	t.Helper()
	result, err := set.Exchange(public, secret)
	if !errors.Is(err, want) || result != ([SharedSecretSize]byte{}) {
		t.Fatalf("exchange: got %v, want %v", err, want)
	}
}

func TestInvalidParameterSet(t *testing.T) {
	for _, set := range []ParameterSet{6, 255} {
		if set.SecretKeySize() != 0 || set.PublicKeySize() != 0 || set.FieldElementSize() != 0 || set.SecurityBits() != 0 {
			t.Fatal("invalid set has sizes")
		}
		if set.String() != fmt.Sprintf("ParameterSet(%d)", uint8(set)) {
			t.Fatal("invalid set string")
		}
		pk, sk, err := set.GenerateKey(nil)
		if !errors.Is(err, ErrParameterSet) || pk != nil || sk != nil {
			t.Fatal("generated invalid set")
		}
		if _, err := set.PublicKeyFromSecretKey(nil); !errors.Is(err, ErrParameterSet) {
			t.Fatal("derived invalid set")
		}
		if _, err := set.ParseSecretKey(nil); !errors.Is(err, ErrParameterSet) {
			t.Fatal("parsed invalid set scalar")
		}
		if _, err := set.ParsePublicKey(nil); !errors.Is(err, ErrParameterSet) {
			t.Fatal("parsed invalid set public key")
		}
		checkExchangeError(t, set, nil, nil, ErrParameterSet)
		result, err := set.HashSharedSecret(nil)
		if !errors.Is(err, ErrParameterSet) || result != ([SharedSecretSize]byte{}) {
			t.Fatal("hashed invalid set")
		}
	}
}

func TestAllParameterFieldExponents(t *testing.T) {
	for _, set := range parameterSets {
		t.Run(set.String(), func(t *testing.T) {
			f, _ := set.parameters()
			for _, x := range []fp{f.fpSmall(0), f.fpSmall(1), f.fpSmall(2), f.fpNeg(f.fpSmall(1))} {
				if f.fpAdd(f.fpHalf(x), f.fpHalf(x)).Equal(x) != 1 {
					t.Fatal("halving mismatch")
				}
				product := f.fpMul(x, f.fpInv(x))
				if x.IsZero() == 0 && f.fpIsOne(product) != 1 {
					t.Fatal("inversion mismatch")
				}
				if x.IsZero() == 1 && product.IsZero() != 1 {
					t.Fatal("inverse of zero differs from C")
				}
			}
			for _, x := range []fp2{f.fp2Small(0), f.fp2Small(1), {f.fpSmall(0), f.fpSmall(1)}, {f.fpSmall(17), f.fpSmall(23)}} {
				square := f.fp2Sqr(x)
				root, ok := f.fp2Sqrt(square)
				if !ok || !f.fp2IsSquare(square) || f.fp2EqualChoice(f.fp2Sqr(root), square) != 1 {
					t.Fatal("square root mismatch")
				}
				if f.fpIsOdd(root.re)|(root.re.IsZero()&f.fpIsOdd(root.im)) != 0 {
					t.Fatal("noncanonical square root sign")
				}
			}
		})
	}
}
