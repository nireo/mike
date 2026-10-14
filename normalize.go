// SPDX-License-Identifier: Apache-2.0

package mike

import "crypto/subtle"

// ecMontgomeryCoefficient maps to ec_compute_montgomery_coefficient:
// (2*(x^4+z^4) : x^4-z^4).
func (f *parameters) ecMontgomeryCoefficient(th ecPoint) ecPoint {
	xx, zz := f.fp2Sqr(f.fp2Sqr(th.x)), f.fp2Sqr(f.fp2Sqr(th.z))
	sum := f.fp2Add(xx, zz)
	return ecPoint{f.fp2Add(sum, sum), f.fp2Sub(xx, zz)}
}

// ecFP2LessThan compares encodings as little-endian integers, with the
// imaginary component most significant, matching ec_fp2_less_than in C.
func (f *parameters) ecFP2LessThan(x, y fp2) int {
	var bx, by [maxPublicKeySize]byte
	f.fp2Encode(bx[:], x)
	f.fp2Encode(by[:], y)
	less, equal := 0, 1
	for i := f.publicBytes - 1; i >= 0; i-- {
		less |= equal & (1 - subtle.ConstantTimeLessOrEq(int(by[i]), int(bx[i])))
		equal &= subtle.ConstantTimeByteEq(bx[i], by[i])
	}
	return less
}

// ecNormalizeMontgomery maps to ec_theta_to_montgomery with weil_rest=2.
// Choose the largest of six Montgomery coefficients and their conjugates.
func (f *parameters) ecNormalizeMontgomery(th ecPoint) (fp2, bool) {
	ia, ib := f.fp2MulByI(th.x), f.fp2MulByI(th.z)
	mont := [3]ecPoint{
		f.ecMontgomeryCoefficient(th),
		f.ecMontgomeryCoefficient(ecPoint{f.fp2Add(th.x, th.z), f.fp2Sub(th.x, th.z)}),
		f.ecMontgomeryCoefficient(ecPoint{f.fp2Add(ia, th.z), f.fp2Add(th.x, ib)}),
	}
	// Batch inversion, matching fp2_batched_inv: one prime-field exponentiation.
	product01 := f.fp2Mul(mont[0].z, mont[1].z)
	product := f.fp2Mul(product01, mont[2].z)
	valid := 1 - f.fp2ZeroChoice(product)
	// Inversion maps zero to zero, so finish the same arithmetic for invalid
	// public theta points. Key generation's full-order kernel guarantees
	// validity; see ecIsogeny2Chain.
	inverse := f.fp2Inv(product)
	denominators := [3]fp2{
		f.fp2Mul(f.fp2Mul(inverse, mont[2].z), mont[1].z),
		f.fp2Mul(f.fp2Mul(inverse, mont[2].z), mont[0].z),
		f.fp2Mul(inverse, product01),
	}
	var coefficients [12]fp2
	for i := 0; i < 3; i++ {
		coefficients[i] = f.fp2Mul(mont[i].x, denominators[i])
		coefficients[i+3] = f.fp2Neg(coefficients[i])
	}
	for i := 0; i < 6; i++ {
		coefficients[i+6] = f.fp2Frob(coefficients[i])
	}
	max := coefficients[0]
	for _, a := range coefficients[1:] {
		max = f.fp2Select(max, a, f.ecFP2LessThan(max, a))
	}
	return max, valid == 1
}
