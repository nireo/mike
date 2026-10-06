package mike

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

func TestReferenceExchanges(t *testing.T) {
	v := readVectors(t)
	if len(v.Exchanges) != 6 {
		t.Fatal("missing C exchange vectors")
	}
	for _, exchange := range v.Exchanges {
		t.Run(fmt.Sprintf("%d-%d", exchange.Alice, exchange.Bob), func(t *testing.T) {
			t.Parallel()
			aliceSK, err := ParseSecretKey(decodeHex(t, v.Keypairs[exchange.Alice].SecretKey))
			if err != nil {
				t.Fatal(err)
			}
			bobSK, err := ParseSecretKey(decodeHex(t, v.Keypairs[exchange.Bob].SecretKey))
			if err != nil {
				t.Fatal(err)
			}
			alicePK, err := ParsePublicKey(decodeHex(t, v.Keypairs[exchange.Alice].PublicKey))
			if err != nil {
				t.Fatal(err)
			}
			bobPK, err := ParsePublicKey(decodeHex(t, v.Keypairs[exchange.Bob].PublicKey))
			if err != nil {
				t.Fatal(err)
			}
			// Check the raw invariants as well as the hashed exchange output.
			invariants, err := defaultParameters.exchangeInvariants(bobPK[:], aliceSK[:])
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(invariants[:]); got != exchange.Invariants {
				t.Fatalf("invariants:\ngot  %s\nwant %s", got, exchange.Invariants)
			}
			aliceShared, err := Exchange(bobPK, aliceSK)
			if err != nil {
				t.Fatal(err)
			}
			bobShared, err := Exchange(alicePK, bobSK)
			if err != nil {
				t.Fatal(err)
			}
			if aliceShared != bobShared {
				t.Fatal("parties disagree")
			}
			if got := hex.EncodeToString(aliceShared[:]); got != exchange.SharedSecret {
				t.Fatalf("shared secret: got %s, want %s", got, exchange.SharedSecret)
			}
		})
	}
}

func TestGeneratedExchange(t *testing.T) {
	alicePK, aliceSK, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	bobPK, bobSK, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Exchange(bobPK, aliceSK)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Exchange(alicePK, bobSK)
	if err != nil {
		t.Fatal(err)
	}
	if a != b || a == ([SharedSecretSize]byte{}) {
		t.Fatal("invalid generated agreement")
	}
}

func TestExchangeRejectsInvalidKeys(t *testing.T) {
	v := readVectors(t)
	sk, err := ParseSecretKey(decodeHex(t, v.Keypairs[0].SecretKey))
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ParsePublicKey(decodeHex(t, v.Keypairs[1].PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	badSK := sk
	badSK[0] = 0
	result, err := Exchange(pk, badSK)
	if !errors.Is(err, ErrSecretKey) || result != ([SharedSecretSize]byte{}) {
		t.Fatalf("invalid scalar: %v", err)
	}
	badSK = sk
	badSK[SecretKeySize-1] = 0x80
	result, err = Exchange(pk, badSK)
	if !errors.Is(err, ErrSecretKey) || result != ([SharedSecretSize]byte{}) {
		t.Fatalf("invalid scalar high bit: %v", err)
	}
	for i := 0; i < 2; i++ {
		badPK := pk
		copy(badPK[i*FieldElementSize:(i+1)*FieldElementSize], bytes.Repeat([]byte{0xff}, FieldElementSize))
		result, err = Exchange(badPK, sk)
		if !errors.Is(err, ErrPublicKey) || result != ([SharedSecretSize]byte{}) {
			t.Fatalf("invalid encoding: %v", err)
		}
	}
	for _, real := range []uint{0, 1, 2} {
		var badPK PublicKey
		defaultParameters.fp2Encode(badPK[:], defaultParameters.fp2Small(real))
		result, err = Exchange(badPK, sk)
		if !errors.Is(err, ErrExchange) || result != ([SharedSecretSize]byte{}) {
			t.Fatalf("invalid curve: %v", err)
		}
	}
	// Canonical, strictly Fp2 curves still need to pass the gluing/order checks.
	for _, a := range []fp2{{defaultParameters.fpSmall(0), defaultParameters.fpSmall(1)}, {defaultParameters.fpSmall(1), defaultParameters.fpSmall(1)}} {
		var badPK PublicKey
		defaultParameters.fp2Encode(badPK[:], a)
		result, err = Exchange(badPK, sk)
		if !errors.Is(err, ErrExchange) || result != ([SharedSecretSize]byte{}) {
			t.Fatalf("invalid Fp2 curve: %v", err)
		}
	}
	// An isomorphic curve still must use the protocol's maximal coefficient.
	re, _ := defaultParameters.fpDecode(pk[:FieldElementSize])
	im, _ := defaultParameters.fpDecode(pk[FieldElementSize:])
	for _, a := range []fp2{defaultParameters.fp2Neg(fp2{re, im}), defaultParameters.fp2Frob(fp2{re, im})} {
		var badPK PublicKey
		defaultParameters.fp2Encode(badPK[:], a)
		result, err = Exchange(badPK, sk)
		if !errors.Is(err, ErrExchange) || result != ([SharedSecretSize]byte{}) {
			t.Fatalf("non-normalized curve: %v", err)
		}
	}
}

func BenchmarkExchange(b *testing.B) {
	v := readVectors(b)
	sk, err := ParseSecretKey(decodeHex(b, v.Keypairs[0].SecretKey))
	if err != nil {
		b.Fatal(err)
	}
	pk, err := ParsePublicKey(decodeHex(b, v.Keypairs[1].PublicKey))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Exchange(pk, sk); err != nil {
			b.Fatal(err)
		}
	}
}
