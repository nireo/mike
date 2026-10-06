package mike

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"testing"
	"testing/iotest"
)

type referenceVectors struct {
	ParameterSet string            `json:"parameter_set"`
	Constants    map[string]string `json:"constants"`
	Keypairs     []struct {
		Seed      string `json:"seed"`
		SecretKey string `json:"secret_key"`
		PublicKey string `json:"public_key"`
	} `json:"keypairs"`
	Invariants string `json:"invariants"`
	SharedHash string `json:"shared_hash"`
	Exchanges  []struct {
		Alice        int    `json:"alice"`
		Bob          int    `json:"bob"`
		Invariants   string `json:"invariants"`
		SharedSecret string `json:"shared_secret"`
	} `json:"exchanges"`
}

func readVectors(t testing.TB) referenceVectors {
	t.Helper()
	return readParameterVectors(t, P308_633)
}

func readParameterVectors(t testing.TB, set ParameterSet) referenceVectors {
	t.Helper()
	b, err := os.ReadFile("testdata/" + set.String() + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors referenceVectors
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.ParameterSet != set.String() || len(vectors.Keypairs) != 8 || len(vectors.Exchanges) != 6 {
		t.Fatal("unexpected reference vectors")
	}
	return vectors
}

func decodeHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReferenceKeypairs(t *testing.T) {
	for _, v := range readVectors(t).Keypairs {
		t.Run(v.Seed[:8], func(t *testing.T) {
			t.Parallel()
			seed := bytes.NewReader(decodeHex(t, v.Seed))
			// io.ReadFull must also handle readers that return partial reads.
			pk, sk, err := GenerateKey(iotest.HalfReader(seed))
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(sk[:]); got != v.SecretKey {
				t.Fatalf("secret key: got %s, want %s", got, v.SecretKey)
			}
			if got := hex.EncodeToString(pk[:]); got != v.PublicKey {
				t.Fatalf("public key: got %s, want %s", got, v.PublicKey)
			}
			if seed.Len() != 0 {
				t.Fatal("did not consume exactly 29 bytes")
			}
			parsedSK, err := ParseSecretKey(sk[:])
			if err != nil || parsedSK != sk {
				t.Fatalf("parse secret key: %v", err)
			}
			parsedPK, err := ParsePublicKey(pk[:])
			if err != nil || parsedPK != pk {
				t.Fatalf("parse public key: %v", err)
			}
			derived, err := PublicKeyFromSecretKey(parsedSK)
			if err != nil || derived != pk {
				t.Fatalf("derive public key: %v", err)
			}
		})
	}
}

func TestReferenceConstants(t *testing.T) {
	v := readVectors(t)
	constants := map[string]fp{
		"a0": defaultParameters.curveA.re, "basis_p": defaultParameters.basisP.x.re, "basis_q": defaultParameters.basisQ.x.re,
		"basis_p_minus_q_re": defaultParameters.basisPmQ.x.re, "basis_p_minus_q_im": defaultParameters.basisPmQ.x.im,
	}
	for name, x := range constants {
		var encoded [FieldElementSize]byte
		defaultParameters.fpEncode(encoded[:], x)
		if got := hex.EncodeToString(encoded[:]); got != v.Constants[name] {
			t.Fatalf("constant %s: %s", name, got)
		}
	}
}

func TestHashSharedSecret(t *testing.T) {
	v := readVectors(t)
	got, err := HashSharedSecret(decodeHex(t, v.Invariants))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:]) != v.SharedHash {
		t.Fatalf("hash mismatch: %x", got)
	}
}

func TestGenerateKeyRandomnessFailure(t *testing.T) {
	readerErr := errors.New("entropy source failed")
	for _, tc := range []struct {
		name   string
		reader io.Reader
		want   error
	}{
		{"empty", bytes.NewReader(nil), io.EOF},
		{"short", bytes.NewReader(make([]byte, SecretKeySize-1)), io.ErrUnexpectedEOF},
		{"error", iotest.ErrReader(readerErr), readerErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pk, sk, err := GenerateKey(tc.reader)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if pk != (PublicKey{}) || sk != (SecretKey{}) {
				t.Fatal("returned a partial key pair")
			}
		})
	}
}

func TestGenerateKeyDefaultRandomness(t *testing.T) {
	pk, sk, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !defaultParameters.validSecretKey(sk[:]) {
		t.Fatal("sampling constraints not satisfied")
	}
	if _, err := ParsePublicKey(pk[:]); err != nil {
		t.Fatal(err)
	}
}

func TestSecretKeyValidation(t *testing.T) {
	valid := SecretKey{3}
	for _, length := range []int{0, SecretKeySize - 1, SecretKeySize + 1} {
		if _, err := ParseSecretKey(make([]byte, length)); !errors.Is(err, ErrSecretKey) {
			t.Fatalf("accepted secret key length %d", length)
		}
	}
	for bit := 0; bit < 8; bit++ {
		if bit == 3 {
			continue
		}
		sk := valid
		sk[0] = byte(bit)
		if _, err := ParseSecretKey(sk[:]); !errors.Is(err, ErrSecretKey) {
			t.Fatal("accepted invalid low bits")
		}
		if _, err := PublicKeyFromSecretKey(sk); !errors.Is(err, ErrSecretKey) {
			t.Fatal("derived invalid key")
		}
	}
	for bit := 4; bit < 8; bit++ {
		sk := valid
		sk[SecretKeySize-1] = 1 << bit
		if _, err := ParseSecretKey(sk[:]); !errors.Is(err, ErrSecretKey) {
			t.Fatal("accepted high bits")
		}
		if _, err := PublicKeyFromSecretKey(sk); !errors.Is(err, ErrSecretKey) {
			t.Fatal("derived invalid key")
		}
	}
	encoded := valid[:]
	sk, err := ParseSecretKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	encoded[1] = 1
	if sk[1] != 0 {
		t.Fatal("parser retained caller's backing slice")
	}
}

func TestCanonicalEncodings(t *testing.T) {
	p := slices.Clone(defaultParameters.primeBytes)
	slices.Reverse(p)
	for _, length := range []int{0, PublicKeySize - 1, PublicKeySize + 1} {
		if _, err := ParsePublicKey(make([]byte, length)); !errors.Is(err, ErrPublicKey) {
			t.Fatalf("accepted public key length %d", length)
		}
	}
	for _, length := range []int{0, 4*FieldElementSize - 1, 4*FieldElementSize + 1} {
		if _, err := HashSharedSecret(make([]byte, length)); !errors.Is(err, ErrInvariants) {
			t.Fatalf("accepted invariant length %d", length)
		}
	}
	for _, bad := range [][]byte{p, bytes.Repeat([]byte{0xff}, FieldElementSize)} {
		for i := 0; i < 2; i++ {
			var encoded PublicKey
			copy(encoded[i*FieldElementSize:], bad)
			if _, err := ParsePublicKey(encoded[:]); !errors.Is(err, ErrPublicKey) {
				t.Fatal("accepted noncanonical component")
			}
		}
		for i := 0; i < 4; i++ {
			encoded := make([]byte, 4*FieldElementSize)
			copy(encoded[i*FieldElementSize:], bad)
			if _, err := HashSharedSecret(encoded); !errors.Is(err, ErrInvariants) {
				t.Fatal("accepted noncanonical invariant")
			}
		}
	}
	// Zero and p-1 are canonical, even though this does not validate a curve.
	var boundary PublicKey
	copy(boundary[:], p)
	boundary[0]--
	parsed, err := ParsePublicKey(boundary[:])
	if err != nil || parsed != boundary {
		t.Fatalf("rejected canonical boundary: %v", err)
	}
	boundary[0]--
	if parsed[0] == boundary[0] {
		t.Fatal("parser retained caller's backing slice")
	}
	if _, err := ParsePublicKey(make([]byte, PublicKeySize)); err != nil {
		t.Fatal(err)
	}
}
