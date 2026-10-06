// SPDX-License-Identifier: Apache-2.0

package mike

import "crypto/subtle"

// ecMontgomeryCoefficient maps to ec_compute_montgomery_coefficient:
// (2*(x^4+z^4) : x^4-z^4).
func ecMontgomeryCoefficient(th ecPoint) ecPoint {
	xx, zz := fp2Sqr(fp2Sqr(th.x)), fp2Sqr(fp2Sqr(th.z))
	sum := fp2Add(xx, zz)
	return ecPoint{fp2Add(sum, sum), fp2Sub(xx, zz)}
}

// ecFP2LessThan compares encodings as little-endian integers, with the
// imaginary component most significant, matching ec_fp2_less_than in C.
func ecFP2LessThan(x, y fp2) int {
	var bx, by [PublicKeySize]byte
	fp2Encode(bx[:], x)
	fp2Encode(by[:], y)
	less, equal := 0, 1
	for i := len(bx) - 1; i >= 0; i-- {
		less |= equal & (1 - subtle.ConstantTimeLessOrEq(int(by[i]), int(bx[i])))
		equal &= subtle.ConstantTimeByteEq(bx[i], by[i])
	}
	return less
}

// ecNormalizeMontgomery maps to ec_theta_to_montgomery with weil_rest=2.
// Choose the largest of six Montgomery coefficients and their conjugates.
func ecNormalizeMontgomery(th ecPoint) (fp2, bool) {
	ia, ib := fp2MulByI(th.x), fp2MulByI(th.z)
	mont := [3]ecPoint{
		ecMontgomeryCoefficient(th),
		ecMontgomeryCoefficient(ecPoint{fp2Add(th.x, th.z), fp2Sub(th.x, th.z)}),
		ecMontgomeryCoefficient(ecPoint{fp2Add(ia, th.z), fp2Add(th.x, ib)}),
	}
	// Batch inversion, matching fp2_batched_inv: one prime-field exponentiation.
	product01 := fp2Mul(mont[0].z, mont[1].z)
	product := fp2Mul(product01, mont[2].z)
	if fp2IsZero(product) {
		return fp2{}, false
	}
	inverse := fp2Inv(product)
	denominators := [3]fp2{
		fp2Mul(fp2Mul(inverse, mont[2].z), mont[1].z),
		fp2Mul(fp2Mul(inverse, mont[2].z), mont[0].z),
		fp2Mul(inverse, product01),
	}
	var coefficients [12]fp2
	for i := 0; i < 3; i++ {
		coefficients[i] = fp2Mul(mont[i].x, denominators[i])
		coefficients[i+3] = fp2Neg(coefficients[i])
	}
	for i := 0; i < 6; i++ {
		coefficients[i+6] = fp2Frob(coefficients[i])
	}
	max := coefficients[0]
	for _, a := range coefficients[1:] {
		max = fp2Select(max, a, ecFP2LessThan(max, a))
	}
	return max, true
}
