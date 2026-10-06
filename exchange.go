// SPDX-License-Identifier: Apache-2.0

package mike

import "errors"

// ErrExchange indicates that the peer key failed the protocol's curve or
// gluing checks, or that the resulting invariants were all zero.
var ErrExchange = errors.New("mike: invalid peer curve or exchange invariants")

// Exchange computes the 32-byte p308_633 shared secret from a peer's public
// key and our secret key, matching mike_exchange in C. It validates both key
// encodings and the protocol's gluing conditions; errors return a zero secret.
func Exchange(peer PublicKey, secret SecretKey) ([SharedSecretSize]byte, error) {
	return P308_633.Exchange(peer[:], secret[:])
}

// The raw invariant encoding is kept internal; hashing is part of Exchange.
func (f *parameters) exchangeInvariants(peer, secret []byte) ([]byte, error) {
	a, err := f.decodePublicKey(peer)
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, 4*f.fieldBytes)
	a24 := f.fp2Half(f.fp2Half(f.fp2Add(a, f.fp2Small(2))))
	p, q, ok := f.ecBasis(a, a24)
	if !ok {
		return nil, ErrExchange
	}
	p32, q32 := f.ecJacDblIter(p, f.chainLength+f.hdMargin-5, a), f.ecJacDblIter(q, f.chainLength+f.hdMargin-5, a)
	gluingBasis := f.gluingBasisCompute(p32, q32, secret, a, a24)
	gluing, ok := f.gluingMikeCompute(a, gluingBasis)
	if !ok {
		return nil, ErrExchange
	}
	basis := f.mikeComputeBasis(p, q, secret, a, a24)
	t3 := f.gluingMikeEval(basis.t31, basis.t32, gluing)
	t4 := f.gluingMikeEval(basis.t41, basis.t42, gluing)
	invDual := f.isogenyChainWeil(gluing.weil.invDual, gluing.weil.pre, t3, t4)
	invariants := f.mikeAbsoluteInvariants(f.thetaInvWeil(invDual))
	allZero := uint(1)
	for i, x := range invariants {
		allZero &= x.IsZero()
		f.fpEncode(encoded[i*f.fieldBytes:(i+1)*f.fieldBytes], x)
	}
	if allZero == 1 {
		return nil, ErrExchange
	}
	return encoded, nil
}
