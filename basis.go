// SPDX-License-Identifier: Apache-2.0

package mike

// Deterministic entangled basis generation from ec/ref/lvlx/basis.c. All
// searches depend only on the peer's public curve. Bound the searches so a
// malformed public key cannot cause an unbounded loop.
const basisSearchLimit = 256

func (f *parameters) ecOnCurve(x, a fp2) bool {
	return f.fp2IsSquare(f.fp2Mul(x, f.fp2Add(f.fp2Add(f.fp2Sqr(x), f.fp2Mul(a, x)), f.fp2Small(1))))
}

func (f *parameters) ecBasis(a, a24 fp2) (ecJacPoint, ecJacPoint, bool) {
	// The protocol's Scholten check requires A to be strictly in Fp2.
	if a.im.IsZero() == 1 {
		return ecJacPoint{}, ecJacPoint{}, false
	}
	var x fp2
	found := false
	if !f.fp2IsSquare(a) {
		x = a
		for n := 0; n < basisSearchLimit; n++ {
			if f.ecOnCurve(x, a) {
				found = true
				break
			}
			x = f.fp2Add(x, a)
		}
	} else {
		a2 := f.fp2Sqr(a)
		for n := uint(1); n <= basisSearchLimit; n++ {
			if f.fpIsSquare(f.fpSmall(n*n + 1)) {
				continue
			}
			z := fp2{f.fpSmall(1), f.fpSmall(n)}
			t := f.fp2Sub(f.fp2Mul(fp2{f.fpSmall(0), z.im}, a2), f.fp2Sqr(z))
			if !f.fp2IsSquare(t) {
				x = f.fp2Neg(f.fp2Mul(f.fp2Inv(z), a))
				found = true
				break
			}
		}
	}
	if !found {
		return ecJacPoint{}, ecJacPoint{}, false
	}
	p, q := ecPoint{x, f.fp2Small(1)}, ecPoint{f.fp2Neg(f.fp2Add(a, x)), f.fp2Small(1)}
	// The ladder supplies the cofactor's leading bit implicitly.
	p, _ = f.ecMulShifted(p, f.cofactorLE, f.cofactorBits-1, 0, a24)
	q, _ = f.ecMulShifted(q, f.cofactorLE, f.cofactorBits-1, 0, a24)
	curve := ecPoint{a24, f.fp2Small(1)}
	for i := 0; i < f.torsionPower-(f.chainLength+f.hdMargin); i++ {
		p, q = f.ecDblA24(p, curve), f.ecDblA24(q, curve)
	}
	pj, ok := f.ecXZToJac(p, a)
	if !ok {
		return ecJacPoint{}, ecJacPoint{}, false
	}
	qj, ok := f.ecXZToJac(q, a)
	if !ok {
		return ecJacPoint{}, ecJacPoint{}, false
	}
	// For nonzero A, Q=P+PQ is the basis point above (0,0).
	return pj, f.ecJacAdd(pj, qj, a), true
}

type chainBasis struct{ t31, t32, t41, t42 ecJacPoint }
type gluingBasis struct{ p8, q8, p16, q16, t31, t32, t41, t42 ecJacPoint }

func (f *parameters) mikeComputeBasis(p, q ecJacPoint, sk []byte, a, a24 fp2) chainBasis {
	t32 := f.ecJacMul(q, sk, f.chainLength+f.hdMargin, 1, a, a24)
	minusP := f.ecJacNeg(p)
	t42 := f.ecJacMul(minusP, sk, f.chainLength+f.hdMargin, 1, a, a24)
	return chainBasis{f.ecJacAdd(t32, q, a), t32, f.ecJacAdd(t42, minusP, a), t42}
}

func (f *parameters) gluingBasisCompute(p32, q32 ecJacPoint, sk []byte, a, a24 fp2) gluingBasis {
	p16, q16 := f.ecJacDbl(p32, a), f.ecJacDbl(q32, a)
	k := []byte{sk[0] >> 1 & 31}
	t32 := f.ecJacMul(q32, k, 5, 0, a, a24)
	minusP := f.ecJacNeg(p32)
	t42 := f.ecJacMul(minusP, k, 5, 0, a, a24)
	return gluingBasis{f.ecJacDbl(p16, a), f.ecJacDbl(q16, a), p16, q16,
		f.ecJacAdd(t32, q32, a), t32, f.ecJacAdd(t42, minusP, a), t42}
}
