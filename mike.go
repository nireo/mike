// SPDX-License-Identifier: Apache-2.0

// Package mike implements MIKE p308_633 key generation and wire encodings.
// Key exchange is not yet implemented.
package mike

import (
	"crypto/rand"
	"crypto/sha3"
	"errors"
	"fmt"
	"io"
)

// Sizes for p308_633, from mike_c/src/precomp/ref/p308_633/include/encoded_sizes.h.
const (
	SecretKeySize        = 29
	PublicKeySize        = 80
	SharedSecretSize     = 32
	FieldElementSize     = 40
	secretKeyBits        = 228
	secretKeyChainLength = 228
	hdMargin             = 2
)

var (
	ErrSecretKey  = errors.New("mike: invalid p308_633 secret key")
	ErrPublicKey  = errors.New("mike: invalid p308_633 public key encoding")
	ErrInvariants = errors.New("mike: invalid p308_633 invariant encoding")
)

// SecretKey is a 228-bit scalar encoded in little-endian order.
// Generated keys have their low three bits set to 3 and their top four bits clear.
type SecretKey [SecretKeySize]byte

// PublicKey encodes the Montgomery curve coefficient A as real || imaginary,
// with each component a canonical 40-byte little-endian integer modulo p.
type PublicKey [PublicKeySize]byte

// GenerateKey generates a p308_633 key pair. A nil random uses crypto/rand.Reader.
// It follows protocols_keygen in mike_c/src/nike/ref/lvlx/keygen.c.
func GenerateKey(random io.Reader) (PublicKey, SecretKey, error) {
	if random == nil {
		random = rand.Reader
	}
	var sk SecretKey
	if _, err := io.ReadFull(random, sk[:]); err != nil {
		return PublicKey{}, SecretKey{}, fmt.Errorf("mike: read randomness: %w", err)
	}
	sk[0] = sk[0]&^7 | 3
	sk[SecretKeySize-1] &= (1 << (secretKeyBits % 8)) - 1
	pk, err := PublicKeyFromSecretKey(sk)
	if err != nil {
		return PublicKey{}, SecretKey{}, err
	}
	return pk, sk, nil
}

// PublicKeyFromSecretKey computes the public key for a valid p308_633 secret key.
func PublicKeyFromSecretKey(sk SecretKey) (PublicKey, error) {
	if !validSecretKey(sk) {
		return PublicKey{}, ErrSecretKey
	}
	kernel := ecLadder3pt(basisP, basisQ, basisPmQ, sk, curveA24)
	a, ok := ecIsogeny2Chain(kernel, curveA24, secretKeyChainLength+hdMargin)
	if !ok {
		return PublicKey{}, errors.New("mike: curve normalization failed")
	}
	var pk PublicKey
	fp2Encode(pk[:], a)
	return pk, nil
}

// ParseSecretKey copies a C-format secret key, checking the sampling constraints.
// This is stricter than the C decoder, which accepts any SECRETKEY_BYTES bytes.
func ParseSecretKey(encoded []byte) (SecretKey, error) {
	if len(encoded) != SecretKeySize {
		return SecretKey{}, ErrSecretKey
	}
	sk := SecretKey(encoded)
	if !validSecretKey(sk) {
		return SecretKey{}, ErrSecretKey
	}
	return sk, nil
}

func validSecretKey(sk SecretKey) bool {
	return sk[0]&7 == 3 && sk[SecretKeySize-1]>>4 == 0
}

// ParsePublicKey copies a C-format public key and checks that both field
// components are canonical. Like public_key_from_bytes in C, this checks only
// the encoding; it does not check curve membership or supersingularity.
func ParsePublicKey(encoded []byte) (PublicKey, error) {
	if len(encoded) != PublicKeySize {
		return PublicKey{}, ErrPublicKey
	}
	if _, err := fpDecode(encoded[:FieldElementSize]); err != nil {
		return PublicKey{}, ErrPublicKey
	}
	if _, err := fpDecode(encoded[FieldElementSize:]); err != nil {
		return PublicKey{}, ErrPublicKey
	}
	return PublicKey(encoded), nil
}

// HashSharedSecret hashes four canonical little-endian field invariants with
// SHA3-256, matching hash_shared_secret in mike_c/src/nike/ref/lvlx/encode.c.
// The caller must supply the 160-byte invariant encoding; this function does
// not compute the invariants or perform a key exchange.
func HashSharedSecret(encodedInvariants []byte) ([SharedSecretSize]byte, error) {
	if len(encodedInvariants) != 4*FieldElementSize {
		return [SharedSecretSize]byte{}, ErrInvariants
	}
	for i := 0; i < 4; i++ {
		if _, err := fpDecode(encodedInvariants[i*FieldElementSize : (i+1)*FieldElementSize]); err != nil {
			return [SharedSecretSize]byte{}, ErrInvariants
		}
	}
	return sha3.Sum256(encodedInvariants), nil
}
