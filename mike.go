// SPDX-License-Identifier: Apache-2.0

// Package mike implements key generation, key exchange, and C-compatible wire
// encodings for all six MIKE parameter sets. The package-level API uses p308_633;
// ParameterSet methods select the other sets.
package mike

import (
	"errors"
	"io"
)

// Sizes for the default p308_633 parameter set.
const (
	SecretKeySize    = 29
	PublicKeySize    = 80
	SharedSecretSize = 32
	FieldElementSize = 40
)

var (
	ErrSecretKey  = errors.New("mike: invalid secret key")
	ErrPublicKey  = errors.New("mike: invalid public key encoding")
	ErrInvariants = errors.New("mike: invalid invariant encoding")
)

// SecretKey is a p308_633 scalar in little-endian order. Generated keys have
// their low three bits set to 3 and their top four bits clear.
type SecretKey [SecretKeySize]byte

// PublicKey encodes the p308_633 curve coefficient A as real || imaginary,
// with each component a canonical 40-byte little-endian integer modulo p.
type PublicKey [PublicKeySize]byte

// GenerateKey generates a p308_633 key pair. A nil random uses crypto/rand.Reader.
func GenerateKey(random io.Reader) (PublicKey, SecretKey, error) {
	public, secret, err := P308_633.GenerateKey(random)
	if err != nil {
		return PublicKey{}, SecretKey{}, err
	}
	return PublicKey(public), SecretKey(secret), nil
}

// PublicKeyFromSecretKey derives the public key for a valid p308_633 scalar.
func PublicKeyFromSecretKey(secret SecretKey) (PublicKey, error) {
	public, err := P308_633.PublicKeyFromSecretKey(secret[:])
	if err != nil {
		return PublicKey{}, err
	}
	return PublicKey(public), nil
}

// ParseSecretKey copies a C-format p308_633 scalar and checks sampling constraints.
func ParseSecretKey(encoded []byte) (SecretKey, error) {
	secret, err := P308_633.ParseSecretKey(encoded)
	if err != nil {
		return SecretKey{}, err
	}
	return SecretKey(secret), nil
}

// ParsePublicKey copies a p308_633 key after checking canonical field encodings.
// It does not check curve membership or supersingularity.
func ParsePublicKey(encoded []byte) (PublicKey, error) {
	public, err := P308_633.ParsePublicKey(encoded)
	if err != nil {
		return PublicKey{}, err
	}
	return PublicKey(public), nil
}

// HashSharedSecret hashes the 160-byte p308_633 encoding of four canonical
// field invariants with SHA3-256. It does not perform a key exchange.
func HashSharedSecret(encoded []byte) ([SharedSecretSize]byte, error) {
	return P308_633.HashSharedSecret(encoded)
}
