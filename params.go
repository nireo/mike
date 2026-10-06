// SPDX-License-Identifier: Apache-2.0

package mike

import (
	"math/big"
	"math/bits"
	"slices"

	"github.com/nireo/mike/internal/bigmod"
)

const maxPublicKeySize = 192

// parameters contains immutable, public data for one parameter set. Every
// arithmetic operation uses this context; there is no mutable active modulus.
type parameters struct {
	name                                               string
	securityBits, fieldBytes, secretBytes, publicBytes int
	secretBits, chainLength, hdMargin, torsionPower    int

	cofactorLE   []byte
	cofactorBits int
	primeBytes   []byte
	prime        *bigmod.Modulus

	inverseExponent, sqrtExponent, progenitorExponent, legendreExponent []byte
	inverseTwo                                                          fp

	curveA, curveA24         fp2
	basisP, basisQ, basisPmQ ecPoint
}

// math/big is used only to initialize public moduli and fixed exponents.
// Secret field operations use the pure Go bigmod backend throughout.
func newParameters(name string, securityBits, fieldBytes, secretBits, chainLength, hdMargin, torsionPower, cofactor int,
	a0, pxRe, pxIm, qxRe, qxIm, pmqxRe, pmqxIm string) *parameters {
	p := new(big.Int).Lsh(big.NewInt(int64(cofactor)), uint(torsionPower))
	p.Sub(p, big.NewInt(1))
	f := &parameters{
		name: name, securityBits: securityBits, fieldBytes: fieldBytes,
		secretBytes: (secretBits + 7) / 8, publicBytes: 2 * fieldBytes,
		secretBits: secretBits, chainLength: chainLength, hdMargin: hdMargin, torsionPower: torsionPower,
		cofactorBits: bits.Len(uint(cofactor)), primeBytes: p.Bytes(),
	}
	f.prime = mustModulus(f.primeBytes)
	f.cofactorLE = big.NewInt(int64(cofactor)).Bytes()
	slices.Reverse(f.cofactorLE)
	f.inverseExponent = new(big.Int).Sub(p, big.NewInt(2)).Bytes()
	f.sqrtExponent = new(big.Int).Rsh(new(big.Int).Add(p, big.NewInt(1)), 2).Bytes()
	f.progenitorExponent = new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(3)), 2).Bytes()
	f.legendreExponent = new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1).Bytes()
	f.inverseTwo = new(bigmod.Nat)
	if _, err := f.inverseTwo.SetBytes(new(big.Int).Rsh(new(big.Int).Add(p, big.NewInt(1)), 1).Bytes(), f.prime); err != nil {
		panic(err)
	}
	f.curveA = fp2{f.mustFP(a0), f.fpSmall(0)}
	f.curveA24 = f.fp2Half(f.fp2Half(f.fp2Add(f.curveA, f.fp2Small(2))))
	f.basisP = ecPoint{fp2{f.mustFP(pxRe), f.mustFP(pxIm)}, f.fp2Small(1)}
	f.basisQ = ecPoint{fp2{f.mustFP(qxRe), f.mustFP(qxIm)}, f.fp2Small(1)}
	f.basisPmQ = ecPoint{fp2{f.mustFP(pmqxRe), f.mustFP(pmqxIm)}, f.fp2Small(1)}
	return f
}

func (f *parameters) mustFP(s string) fp {
	x, err := f.fpDecode(mustHex(s))
	if err != nil {
		panic(err)
	}
	return x
}

var defaultParameters = allParameters[P308_633]
