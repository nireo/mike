// SPDX-License-Identifier: Apache-2.0

package mike

// Deterministic entangled basis generation from ec/ref/lvlx/basis.c. All
// searches depend only on the peer's public curve. Bound the searches so a
// malformed public key cannot cause an unbounded loop.
const basisSearchLimit = 256

func ecOnCurve(x, a fp2) bool {
	return fp2IsSquare(fp2Mul(x, fp2Add(fp2Add(fp2Sqr(x), fp2Mul(a, x)), fp2Small(1))))
}

func ecBasis(a, a24 fp2) (ecJacPoint, ecJacPoint, bool) {
	// The protocol's Scholten check requires A to be strictly in Fp2.
	if a.im.IsZero() == 1 {
		return ecJacPoint{}, ecJacPoint{}, false
	}
	var x fp2
	found := false
	if !fp2IsSquare(a) {
		x = a
		for n := 0; n < basisSearchLimit; n++ {
			if ecOnCurve(x, a) {
				found = true
				break
			}
			x = fp2Add(x, a)
		}
	} else {
		a2 := fp2Sqr(a)
		for n := uint(1); n <= basisSearchLimit; n++ {
			if fpIsSquare(fpSmall(n*n + 1)) {
				continue
			}
			z := fp2{fpSmall(1), fpSmall(n)}
			t := fp2Sub(fp2Mul(fp2{fpSmall(0), z.im}, a2), fp2Sqr(z))
			if !fp2IsSquare(t) {
				x = fp2Neg(fp2Mul(fp2Inv(z), a))
				found = true
				break
			}
		}
	}
	if !found {
		return ecJacPoint{}, ecJacPoint{}, false
	}
	p, q := ecPoint{x, fp2Small(1)}, ecPoint{fp2Neg(fp2Add(a, x)), fp2Small(1)}
	// The implicit leading bit in the ladder supplies bit 9 of 633.
	p, _ = ecMulShifted(p, []byte{0x79, 0x02}, 9, 0, a24)
	q, _ = ecMulShifted(q, []byte{0x79, 0x02}, 9, 0, a24)
	curve := ecPoint{a24, fp2Small(1)}
	for i := 0; i < 308-(secretKeyChainLength+hdMargin); i++ {
		p, q = ecDblA24(p, curve), ecDblA24(q, curve)
	}
	pj, ok := ecXZToJac(p, a)
	if !ok {
		return ecJacPoint{}, ecJacPoint{}, false
	}
	qj, ok := ecXZToJac(q, a)
	if !ok {
		return ecJacPoint{}, ecJacPoint{}, false
	}
	// For nonzero A, Q=P+PQ is the basis point above (0,0).
	return pj, ecJacAdd(pj, qj, a), true
}

type chainBasis struct{ t31, t32, t41, t42 ecJacPoint }
type gluingBasis struct{ p8, q8, p16, q16, t31, t32, t41, t42 ecJacPoint }

func mikeComputeBasis(p, q ecJacPoint, sk SecretKey, a, a24 fp2) chainBasis {
	t32 := ecJacMul(q, sk[:], secretKeyChainLength+hdMargin, 1, a, a24)
	minusP := ecJacNeg(p)
	t42 := ecJacMul(minusP, sk[:], secretKeyChainLength+hdMargin, 1, a, a24)
	return chainBasis{ecJacAdd(t32, q, a), t32, ecJacAdd(t42, minusP, a), t42}
}

func gluingBasisCompute(p32, q32 ecJacPoint, sk SecretKey, a, a24 fp2) gluingBasis {
	p16, q16 := ecJacDbl(p32, a), ecJacDbl(q32, a)
	k := []byte{sk[0] >> 1 & 31}
	t32 := ecJacMul(q32, k, 5, 0, a, a24)
	minusP := ecJacNeg(p32)
	t42 := ecJacMul(minusP, k, 5, 0, a, a24)
	return gluingBasis{ecJacDbl(p16, a), ecJacDbl(q16, a), p16, q16,
		ecJacAdd(t32, q32, a), t32, ecJacAdd(t42, minusP, a), t42}
}
