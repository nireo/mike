package mike

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"math/big"
	"slices"
	"testing"
)

func FuzzParseSecretKey(f *testing.F) {
	for _, set := range parameterSets {
		for _, v := range readParameterVectors(f, set).Keypairs {
			f.Add(uint8(set), decodeHex(f, v.SecretKey))
		}
		f.Add(uint8(set), []byte(nil))
		f.Add(uint8(set), make([]byte, set.SecretKeySize()))
		f.Add(uint8(set), bytes.Repeat([]byte{0xff}, set.SecretKeySize()))
	}
	f.Add(uint8(6), []byte{3})
	f.Add(uint8(255), []byte(nil))
	f.Fuzz(func(t *testing.T, rawSet uint8, encoded []byte) {
		set := ParameterSet(rawSet)
		before := bytes.Clone(encoded)
		parsed, err := set.ParseSecretKey(encoded)
		if !bytes.Equal(encoded, before) {
			t.Fatal("parser mutated its input")
		}
		var want error
		if rawSet >= uint8(len(parameterSets)) {
			want = ErrParameterSet
		} else if !fuzzCanonicalScalar(set, encoded) {
			want = ErrSecretKey
		}
		if !errors.Is(err, want) {
			t.Fatalf("parse: got %v, want %v", err, want)
		}
		if err != nil {
			if parsed != nil {
				t.Fatal("parser returned a key on error")
			}
			public, deriveErr := set.PublicKeyFromSecretKey(encoded)
			if !errors.Is(deriveErr, want) || public != nil {
				t.Fatal("public-key derivation accepted an invalid scalar or set")
			}
			shared, exchangeErr := set.Exchange(nil, encoded)
			if !errors.Is(exchangeErr, want) || shared != ([SharedSecretSize]byte{}) {
				t.Fatal("exchange accepted an invalid scalar or set")
			}
			return
		}
		if !bytes.Equal(parsed, encoded) {
			t.Fatal("parser changed the encoding")
		}
		parsed[0] ^= 0xff
		if !bytes.Equal(encoded, before) {
			t.Fatal("parser retained the caller's backing slice")
		}
	})
}

func FuzzParsePublicKey(f *testing.F) {
	for _, set := range parameterSets {
		for _, v := range readParameterVectors(f, set).Keypairs {
			f.Add(uint8(set), decodeHex(f, v.PublicKey))
		}
		for _, encoded := range fuzzFieldBoundaries(set, 2) {
			f.Add(uint8(set), encoded)
		}
	}
	f.Add(uint8(6), []byte(nil))
	f.Add(uint8(255), []byte{0})
	f.Fuzz(func(t *testing.T, rawSet uint8, encoded []byte) {
		set := ParameterSet(rawSet)
		before := bytes.Clone(encoded)
		parsed, err := set.ParsePublicKey(encoded)
		if !bytes.Equal(encoded, before) {
			t.Fatal("parser mutated its input")
		}
		var want error
		if rawSet >= uint8(len(parameterSets)) {
			want = ErrParameterSet
		} else if !fuzzCanonicalFields(set, encoded, 2) {
			want = ErrPublicKey
		}
		if !errors.Is(err, want) {
			t.Fatalf("parse: got %v, want %v", err, want)
		}
		if err != nil {
			if parsed != nil {
				t.Fatal("parser returned a key on error")
			}
			return
		}
		if !bytes.Equal(parsed, encoded) {
			t.Fatal("parser changed the encoding")
		}
		parsed[0] ^= 0xff
		if !bytes.Equal(encoded, before) {
			t.Fatal("parser retained the caller's backing slice")
		}
	})
}

func FuzzHashSharedSecret(f *testing.F) {
	for _, set := range parameterSets {
		v := readParameterVectors(f, set)
		f.Add(uint8(set), decodeHex(f, v.Invariants))
		for _, exchange := range v.Exchanges {
			f.Add(uint8(set), decodeHex(f, exchange.Invariants))
		}
		for _, encoded := range fuzzFieldBoundaries(set, 4) {
			f.Add(uint8(set), encoded)
		}
	}
	f.Add(uint8(6), []byte(nil))
	f.Add(uint8(255), []byte{0})
	f.Fuzz(func(t *testing.T, rawSet uint8, encoded []byte) {
		set := ParameterSet(rawSet)
		before := bytes.Clone(encoded)
		shared, err := set.HashSharedSecret(encoded)
		if !bytes.Equal(encoded, before) {
			t.Fatal("hashing mutated its input")
		}
		var want error
		if rawSet >= uint8(len(parameterSets)) {
			want = ErrParameterSet
		} else if !fuzzCanonicalFields(set, encoded, 4) {
			want = ErrInvariants
		}
		if !errors.Is(err, want) {
			t.Fatalf("hash: got %v, want %v", err, want)
		}
		if err != nil {
			if shared != ([SharedSecretSize]byte{}) {
				t.Fatal("nonzero shared secret on error")
			}
		} else if shared != sha3.Sum256(encoded) {
			t.Fatal("hash differs from SHA3-256 of the canonical encoding")
		}
	})
}

// Keep the scalar valid and fixed so peer mutations reach curve validation,
// rather than being rejected early by scalar sampling constraints.
func FuzzExchange(f *testing.F) {
	var secrets [6][]byte
	var referenceShared [6]map[string]string
	for _, set := range parameterSets {
		v := readParameterVectors(f, set)
		secrets[set] = decodeHex(f, v.Keypairs[0].SecretKey)
		referenceShared[set] = make(map[string]string)
		for _, exchange := range v.Exchanges {
			if exchange.Alice == 0 {
				peer := decodeHex(f, v.Keypairs[exchange.Bob].PublicKey)
				referenceShared[set][string(peer)] = exchange.SharedSecret
				f.Add(uint8(set), peer)
			}
		}
		for _, encoded := range fuzzFieldBoundaries(set, 2) {
			f.Add(uint8(set), encoded)
		}
		// An ordinary Fp2 curve and non-normalized isomorphic peer curves.
		p := allParameters[set]
		ordinary := make([]byte, set.PublicKeySize())
		ordinary[0], ordinary[set.FieldElementSize()] = 1, 1
		f.Add(uint8(set), ordinary)
		curve, err := p.decodePublicKey(decodeHex(f, v.Keypairs[1].PublicKey))
		if err != nil {
			f.Fatal(err)
		}
		for _, a := range []fp2{p.fp2Neg(curve), p.fp2Frob(curve)} {
			encoded := make([]byte, set.PublicKeySize())
			p.fp2Encode(encoded, a)
			f.Add(uint8(set), encoded)
		}
	}
	f.Add(uint8(6), []byte(nil))
	f.Add(uint8(255), []byte{0})
	f.Fuzz(func(t *testing.T, rawSet uint8, peer []byte) {
		set := ParameterSet(rawSet)
		var secret []byte
		if rawSet < uint8(len(parameterSets)) {
			secret = secrets[set]
		}
		peerBefore, secretBefore := bytes.Clone(peer), bytes.Clone(secret)
		shared, err := set.Exchange(peer, secret)
		if !bytes.Equal(peer, peerBefore) || !bytes.Equal(secret, secretBefore) {
			t.Fatal("exchange mutated a key")
		}
		switch {
		case rawSet >= uint8(len(parameterSets)):
			if !errors.Is(err, ErrParameterSet) {
				t.Fatalf("invalid set: %v", err)
			}
		case !fuzzCanonicalFields(set, peer, 2):
			if !errors.Is(err, ErrPublicKey) {
				t.Fatalf("noncanonical peer: %v", err)
			}
		case bytes.Equal(peer[set.FieldElementSize():], make([]byte, set.FieldElementSize())):
			// MIKE's gluing requires the coefficient to be strictly in Fp2.
			if !errors.Is(err, ErrExchange) {
				t.Fatalf("accepted a curve with a zero imaginary component: %v", err)
			}
		default:
			if err != nil && !errors.Is(err, ErrExchange) {
				t.Fatalf("canonical peer returned unexpected error: %v", err)
			}
			if want, ok := referenceShared[set][string(peer)]; ok {
				if err != nil || hex.EncodeToString(shared[:]) != want {
					t.Fatalf("C exchange mismatch: %v", err)
				}
			}
		}
		if err != nil && shared != ([SharedSecretSize]byte{}) {
			t.Fatal("nonzero shared secret on error")
		}
		if err == nil && shared == ([SharedSecretSize]byte{}) {
			t.Fatal("successful exchange returned a zero shared secret")
		}
	})
}

// Arbitrary entropy is padded or truncated to one scalar's size. This keeps
// mutated inputs on the valid protocol path, including empty and short inputs.
func FuzzKeyExchangeAgreement(f *testing.F) {
	var vectors [6]referenceVectors
	for _, set := range parameterSets {
		vectors[set] = readParameterVectors(f, set)
		for _, exchange := range vectors[set].Exchanges {
			alice := vectors[set].Keypairs[exchange.Alice]
			bob := vectors[set].Keypairs[exchange.Bob]
			f.Add(uint8(set), decodeHex(f, alice.Seed), decodeHex(f, bob.Seed))
		}
	}
	f.Add(uint8(0), []byte(nil), []byte{0xff})
	f.Fuzz(func(t *testing.T, selector uint8, aliceInput, bobInput []byte) {
		// Invalid sets are covered by the other targets; every input here
		// exercises one of the six valid sets.
		set := parameterSets[int(selector)%len(parameterSets)]
		var public, secret [2][]byte
		for i, input := range [][]byte{aliceInput, bobInput} {
			entropy := make([]byte, set.SecretKeySize())
			copy(entropy, input)
			reader := bytes.NewReader(entropy)
			var err error
			public[i], secret[i], err = set.GenerateKey(reader)
			if err != nil {
				t.Fatalf("key generation: %v", err)
			}
			if reader.Len() != 0 || !fuzzCanonicalScalar(set, secret[i]) || !fuzzCanonicalFields(set, public[i], 2) {
				t.Fatal("generated an invalid key pair or consumed incorrect randomness")
			}
			// Retain an independent oracle whenever mutations reproduce a C seed.
			seedHex := hex.EncodeToString(entropy)
			for _, v := range vectors[set].Keypairs {
				if seedHex == v.Seed && (hex.EncodeToString(public[i]) != v.PublicKey || hex.EncodeToString(secret[i]) != v.SecretKey) {
					t.Fatal("C key generation mismatch")
				}
			}
			derived, err := set.PublicKeyFromSecretKey(secret[i])
			if err != nil || !bytes.Equal(derived, public[i]) {
				t.Fatalf("public key derivation mismatch: %v", err)
			}
		}
		alice, err := set.Exchange(public[1], secret[0])
		if err != nil {
			t.Fatalf("Alice exchange: %v", err)
		}
		bob, err := set.Exchange(public[0], secret[1])
		if err != nil || alice != bob || alice == ([SharedSecretSize]byte{}) {
			t.Fatalf("parties disagree or exchange failed: %v", err)
		}
		for _, v := range vectors[set].Exchanges {
			aliceKey, bobKey := vectors[set].Keypairs[v.Alice], vectors[set].Keypairs[v.Bob]
			if hex.EncodeToString(secret[0]) == aliceKey.SecretKey && hex.EncodeToString(secret[1]) == bobKey.SecretKey &&
				hex.EncodeToString(alice[:]) != v.SharedSecret {
				t.Fatal("C shared secret mismatch")
			}
		}
	})
}

// All six sets sample scalars congruent to 3 modulo 8 with four unused top bits.
func fuzzCanonicalScalar(set ParameterSet, encoded []byte) bool {
	return len(encoded) == set.SecretKeySize() && encoded[0]%8 == 3 && encoded[len(encoded)-1] < 16
}

// An integer oracle independent of the bigmod decoder used by the API.
func fuzzCanonicalFields(set ParameterSet, encoded []byte, count int) bool {
	size := set.FieldElementSize()
	if len(encoded) != count*size {
		return false
	}
	p := new(big.Int).SetBytes(allParameters[set].primeBytes)
	for i := 0; i < count; i++ {
		component := bytes.Clone(encoded[i*size : (i+1)*size])
		slices.Reverse(component)
		if new(big.Int).SetBytes(component).Cmp(p) >= 0 {
			return false
		}
	}
	return true
}

func fuzzFieldBoundaries(set ParameterSet, count int) [][]byte {
	size := set.FieldElementSize()
	length := count * size
	seeds := [][]byte{nil, make([]byte, length), make([]byte, length-1), make([]byte, length+1), bytes.Repeat([]byte{0xff}, length)}
	p := bytes.Clone(allParameters[set].primeBytes)
	slices.Reverse(p)
	for i := 0; i < count; i++ {
		encoded := make([]byte, length)
		copy(encoded[i*size:], p)
		seeds = append(seeds, encoded) // p is noncanonical.
		boundary := bytes.Clone(encoded)
		boundary[i*size]-- // p-1 is canonical; every modulus ends in ff.
		seeds = append(seeds, boundary)
	}
	return seeds
}
