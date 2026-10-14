package mike

import (
	"bytes"
	"math/big"
	"math/rand/v2"
	"testing"
)

// The normalization argument relies on these public, precomputed torsion
// points. An odd s makes [2^(n-1)](P+sQ)=P2+Q2 distinct from Q2=(0,0).
func TestKeyGenerationBasisTorsion(t *testing.T) {
	for _, set := range parameterSets {
		t.Run(set.String(), func(t *testing.T) {
			f := allParameters[set]
			if f.fp2IsZero(f.fp2Sub(f.fp2Sqr(f.curveA), f.fp2Small(4))) {
				t.Fatal("key-generation curve is singular")
			}
			a24 := ecPoint{f.curveA24, f.fp2Small(1)}
			p2, q2 := f.basisP, f.basisQ
			for i := 0; i < f.chainLength+f.hdMargin-1; i++ {
				p2, q2 = f.ecDblA24(p2, a24), f.ecDblA24(q2, a24)
			}
			if f.fp2IsZero(p2.z) || f.fp2IsZero(q2.z) ||
				f.fp2IsZero(p2.x) || !f.fp2IsZero(q2.x) {
				t.Fatal("basis must have distinct nonzero 2-torsion with Q2=(0,0)")
			}
			if !f.fp2IsZero(f.ecDblA24(p2, a24).z) ||
				!f.fp2IsZero(f.ecDblA24(q2, a24).z) {
				t.Fatal("basis does not have the expected exact power-of-two order")
			}
		})
	}
}

func TestBoundarySecretAgreement(t *testing.T) {
	for _, set := range parameterSets {
		t.Run(set.String(), func(t *testing.T) {
			t.Parallel()
			f := allParameters[set]
			vectors := readParameterVectors(t, set)
			peer := decodeHex(t, vectors.Keypairs[0].PublicKey)
			peerSecret := decodeHex(t, vectors.Keypairs[0].SecretKey)
			// Exercise every allowed low-six-bit class and both scalar extremes.
			for i := 0; i < 9; i++ {
				secret := make([]byte, f.secretBytes)
				secret[0] = byte(8*i + 3)
				if i == 8 {
					for j := range secret {
						secret[j] = 0xff
					}
					secret[0] = secret[0]&^7 | 3
					secret[len(secret)-1] &= byte((1 << (f.secretBits % 8)) - 1)
				}
				public, err := set.PublicKeyFromSecretKey(secret)
				if err != nil {
					t.Fatalf("scalar class %d: key derivation: %v", i, err)
				}
				a, err := set.Exchange(peer, secret)
				if err != nil {
					t.Fatalf("scalar class %d: exchange: %v", i, err)
				}
				b, err := set.Exchange(public, peerSecret)
				if err != nil || a != b {
					t.Fatalf("scalar class %d: agreement: %v", i, err)
				}
			}
		})
	}
}

func TestFieldCanonicalEncodingAgainstBigInt(t *testing.T) {
	rng := rand.New(rand.NewPCG(0x656e636f64696e67, 0x63616e6f6e696361))
	for _, set := range parameterSets {
		t.Run(set.String(), func(t *testing.T) {
			f := allParameters[set]
			p := new(big.Int).SetBytes(f.primeBytes)
			boundary := []*big.Int{
				new(big.Int), big.NewInt(1),
				new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Set(p),
				new(big.Int).Add(p, big.NewInt(1)),
			}
			for i := 0; i < len(boundary)+256; i++ {
				encoded := make([]byte, f.fieldBytes)
				if i < len(boundary) {
					boundary[i].FillBytes(encoded)
				} else {
					for j := range encoded {
						encoded[j] = byte(rng.Uint32())
					}
				}
				value := new(big.Int).SetBytes(encoded)
				for left, right := 0, len(encoded)-1; left < right; left, right = left+1, right-1 {
					encoded[left], encoded[right] = encoded[right], encoded[left]
				}
				valid := f.fpEncodingCanonical(encoded)
				want := 0
				if value.Cmp(p) < 0 {
					want = 1
				}
				if valid != want {
					t.Fatalf("canonical check differs from big.Int for %x", encoded)
				}
				x, err := f.fpDecode(encoded)
				if valid == 0 {
					if err == nil {
						t.Fatal("canonical check disagrees with the backend decoder")
					}
					continue
				}
				if err != nil {
					t.Fatalf("backend rejected canonical value: %v", err)
				}
				out := make([]byte, f.fieldBytes)
				f.fpEncode(out, x)
				if !bytes.Equal(out, encoded) {
					t.Fatal("canonical value changed during Montgomery conversion")
				}
			}
		})
	}
}

func TestNormalizationDegenerateInputs(t *testing.T) {
	for _, set := range parameterSets {
		t.Run(set.String(), func(t *testing.T) {
			f := allParameters[set]
			zero, one := f.fp2Small(0), f.fp2Small(1)
			for _, point := range []ecPoint{
				{zero, zero}, {zero, one}, {one, zero},
				{one, one}, {one, f.fp2Neg(one)},
				{one, fp2{f.fpSmall(0), f.fpSmall(1)}},
			} {
				coefficient, valid := f.ecNormalizeMontgomery(point)
				if valid || !f.fp2IsZero(coefficient) {
					t.Fatal("degenerate theta point must be rejected with a zero coefficient")
				}
			}
		})
	}
}
