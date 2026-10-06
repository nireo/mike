// SPDX-License-Identifier: Apache-2.0

package mike

import (
	"crypto/sha3"
	"errors"
)

// ErrExchange indicates that the peer key failed the protocol's curve or
// gluing checks, or that the resulting invariants were all zero.
var ErrExchange = errors.New("mike: invalid peer curve or exchange invariants")

// Exchange computes the 32-byte p308_633 shared secret from a peer's public
// key and our secret key, matching mike_exchange in C. It validates both key
// encodings and the protocol's gluing conditions; errors return a zero secret.
func Exchange(peer PublicKey, secret SecretKey) ([SharedSecretSize]byte, error) {
	var zero [SharedSecretSize]byte
	if !validSecretKey(secret) {
		return zero, ErrSecretKey
	}
	invariants, err := exchangeInvariants(peer, secret)
	if err != nil {
		return zero, err
	}
	return sha3.Sum256(invariants[:]), nil
}

// The raw invariant encoding is kept internal; hashing is part of Exchange.
func exchangeInvariants(peer PublicKey, secret SecretKey) ([4 * FieldElementSize]byte, error) {
	var encoded [4 * FieldElementSize]byte
	re, err := fpDecode(peer[:FieldElementSize])
	if err != nil {
		return encoded, ErrPublicKey
	}
	im, err := fpDecode(peer[FieldElementSize:])
	if err != nil {
		return encoded, ErrPublicKey
	}
	a := fp2{re, im}
	a24 := fp2Half(fp2Half(fp2Add(a, fp2Small(2))))
	p, q, ok := ecBasis(a, a24)
	if !ok {
		return encoded, ErrExchange
	}
	p32, q32 := ecJacDblIter(p, secretKeyChainLength+hdMargin-5, a), ecJacDblIter(q, secretKeyChainLength+hdMargin-5, a)
	gluingBasis := gluingBasisCompute(p32, q32, secret, a, a24)
	gluing, ok := gluingMikeCompute(a, gluingBasis)
	if !ok {
		return encoded, ErrExchange
	}
	basis := mikeComputeBasis(p, q, secret, a, a24)
	t3 := gluingMikeEval(basis.t31, basis.t32, gluing)
	t4 := gluingMikeEval(basis.t41, basis.t42, gluing)
	invDual := isogenyChainWeil(gluing.weil.invDual, gluing.weil.pre, t3, t4)
	invariants := mikeAbsoluteInvariants(thetaInvWeil(invDual))
	allZero := uint(1)
	for i, x := range invariants {
		allZero &= x.IsZero()
		fpEncode(encoded[i*FieldElementSize:(i+1)*FieldElementSize], x)
	}
	if allZero == 1 {
		return [4 * FieldElementSize]byte{}, ErrExchange
	}
	return encoded, nil
}
