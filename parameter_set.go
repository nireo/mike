// SPDX-License-Identifier: Apache-2.0

package mike

import (
	"crypto/rand"
	"crypto/sha3"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"slices"
)

// ParameterSet selects a C-compatible MIKE parameter set. Its zero value is
// P308_633. Keys are canonical little-endian byte slices whose sizes depend on
// the set; callers must use the same set for both parties and all operations.
type ParameterSet uint8

const (
	P308_633 ParameterSet = iota
	P374_117
	P474_593
	P566_77
	P628_317
	P758_41
)

var ErrParameterSet = errors.New("mike: invalid parameter set")

func (set ParameterSet) parameters() (*parameters, error) {
	if int(set) >= len(allParameters) {
		return nil, ErrParameterSet
	}
	return allParameters[set], nil
}

// String returns the C parameter-set name, or an invalid value's numeric form.
func (set ParameterSet) String() string {
	if f, err := set.parameters(); err == nil {
		return f.name
	}
	return fmt.Sprintf("ParameterSet(%d)", uint8(set))
}

// SecurityBits returns the reference's security level, or zero for an invalid set.
func (set ParameterSet) SecurityBits() int {
	if f, err := set.parameters(); err == nil {
		return f.securityBits
	}
	return 0
}

// SecretKeySize returns the encoded scalar size, or zero for an invalid set.
func (set ParameterSet) SecretKeySize() int {
	if f, err := set.parameters(); err == nil {
		return f.secretBytes
	}
	return 0
}

// PublicKeySize returns the encoded curve size, or zero for an invalid set.
func (set ParameterSet) PublicKeySize() int {
	if f, err := set.parameters(); err == nil {
		return f.publicBytes
	}
	return 0
}

// FieldElementSize returns the encoded prime-field size, or zero for an invalid set.
func (set ParameterSet) FieldElementSize() int {
	if f, err := set.parameters(); err == nil {
		return f.fieldBytes
	}
	return 0
}

// GenerateKey generates a key pair. A nil reader uses crypto/rand.Reader.
// On error both keys are nil.
func (set ParameterSet) GenerateKey(random io.Reader) (public, secret []byte, err error) {
	f, err := set.parameters()
	if err != nil {
		return nil, nil, err
	}
	if random == nil {
		random = rand.Reader
	}
	secret = make([]byte, f.secretBytes)
	if _, err := io.ReadFull(random, secret); err != nil {
		return nil, nil, fmt.Errorf("mike: read randomness: %w", err)
	}
	secret[0] = secret[0]&^7 | 3
	secret[len(secret)-1] &= byte((1 << (f.secretBits % 8)) - 1)
	public, err = set.PublicKeyFromSecretKey(secret)
	if err != nil {
		return nil, nil, err
	}
	return public, secret, nil
}

func (f *parameters) validSecretKey(secret []byte) bool {
	if len(secret) != f.secretBytes {
		return false
	}
	low := subtle.ConstantTimeByteEq(secret[0]&7, 3)
	high := subtle.ConstantTimeByteEq(secret[len(secret)-1]>>(f.secretBits%8), 0)
	return low&high == 1
}

// PublicKeyFromSecretKey derives a public key after checking the scalar constraints.
// Secret arithmetic and encoding run inside subtle.WithDataIndependentTiming.
func (set ParameterSet) PublicKeyFromSecretKey(secret []byte) (public []byte, err error) {
	f, err := set.parameters()
	if err != nil {
		return nil, err
	}
	if !f.validSecretKey(secret) {
		return nil, ErrSecretKey
	}
	subtle.WithDataIndependentTiming(func() {
		public = f.publicKeyFromSecretKey(secret)
	})
	return public, err
}

func (f *parameters) publicKeyFromSecretKey(secret []byte) []byte {
	kernel := f.ecLadder3pt(f.basisP, f.basisQ, f.basisPmQ, secret, f.curveA24)
	a := f.ecIsogeny2Chain(kernel, f.curveA24, f.chainLength+f.hdMargin)
	public := make([]byte, f.publicBytes)
	f.fp2Encode(public, a)
	return public
}

// ParseSecretKey checks the C sampling constraints and returns an independent copy.
// This is stricter than the C secret decoder, which checks only the byte count.
func (set ParameterSet) ParseSecretKey(encoded []byte) ([]byte, error) {
	f, err := set.parameters()
	if err != nil {
		return nil, err
	}
	if !f.validSecretKey(encoded) {
		return nil, ErrSecretKey
	}
	return slices.Clone(encoded), nil
}

// ParsePublicKey checks both field components are canonical and returns a copy.
// Like the C decoder, it does not check curve membership or supersingularity.
func (set ParameterSet) ParsePublicKey(encoded []byte) ([]byte, error) {
	f, err := set.parameters()
	if err != nil {
		return nil, err
	}
	if _, err := f.decodePublicKey(encoded); err != nil {
		return nil, err
	}
	return slices.Clone(encoded), nil
}

func (f *parameters) decodePublicKey(encoded []byte) (fp2, error) {
	if len(encoded) != f.publicBytes {
		return fp2{}, ErrPublicKey
	}
	reValid := f.fpEncodingCanonical(encoded[:f.fieldBytes])
	imValid := f.fpEncodingCanonical(encoded[f.fieldBytes:])
	if reValid&imValid != 1 {
		return fp2{}, ErrPublicKey
	}
	// Both encodings are canonical, so the backend decoder cannot fail.
	re, _ := f.fpDecode(encoded[:f.fieldBytes])
	im, _ := f.fpDecode(encoded[f.fieldBytes:])
	return fp2{re, im}, nil
}

// Exchange derives the 32-byte shared secret and checks the scalar, public-key
// encoding, and protocol gluing conditions. On error the shared secret is zero.
// Secret arithmetic, encoding, and hashing run inside subtle.WithDataIndependentTiming.
func (set ParameterSet) Exchange(peer, secret []byte) (shared [SharedSecretSize]byte, err error) {
	f, err := set.parameters()
	if err != nil {
		return [SharedSecretSize]byte{}, err
	}
	if !f.validSecretKey(secret) {
		return [SharedSecretSize]byte{}, ErrSecretKey
	}
	subtle.WithDataIndependentTiming(func() {
		var encoded [4 * (maxPublicKeySize / 2)]byte
		invariants := encoded[:4*f.fieldBytes]
		err = f.exchangeInvariants(invariants, peer, secret)
		// Hash even on rejection; the returned status is handled afterwards.
		shared = sha3.Sum256(invariants)
	})
	if err != nil {
		return [SharedSecretSize]byte{}, err
	}
	return shared, nil
}

// HashSharedSecret hashes four canonical field invariants with SHA3-256.
// The encoding must have length 4*set.FieldElementSize().
// All four components are checked before reporting an invalid encoding.
func (set ParameterSet) HashSharedSecret(encoded []byte) (shared [SharedSecretSize]byte, err error) {
	f, err := set.parameters()
	if err != nil {
		return [SharedSecretSize]byte{}, err
	}
	if len(encoded) != 4*f.fieldBytes {
		return [SharedSecretSize]byte{}, ErrInvariants
	}
	valid := 1
	subtle.WithDataIndependentTiming(func() {
		for i := 0; i < 4; i++ {
			valid &= f.fpEncodingCanonical(encoded[i*f.fieldBytes : (i+1)*f.fieldBytes])
		}
		shared = sha3.Sum256(encoded)
	})
	if valid != 1 {
		return [SharedSecretSize]byte{}, ErrInvariants
	}
	return shared, nil
}
