// SPDX-License-Identifier: Apache-2.0

package mike

import "github.com/nireo/mike/internal/bigmod"

func (f *parameters) fpExp(x fp, exponent []byte) fp {
	return new(bigmod.Nat).Exp(x, exponent, f.prime)
}
func (f *parameters) fpHalf(x fp) fp { return f.fpMul(x, f.inverseTwo) }
func (f *parameters) fpIsSquare(x fp) bool {
	return f.fpExp(x, f.legendreExponent).IsOne()|x.IsZero() == 1
}

// fpProjectiveInverse returns products of all coordinates except the selected
// one, matching fp_proj_batched_inv. This preserves the reference's handling
// of zero coordinates without performing an inversion.
func (f *parameters) fpProjectiveInverse(x []fp) []fp {
	prefix := make([]fp, len(x))
	prefix[0] = f.fpSmall(1)
	for i := 1; i < len(x); i++ {
		prefix[i] = f.fpMul(prefix[i-1], x[i-1])
	}
	out := make([]fp, len(x))
	suffix := f.fpSmall(1)
	for i := len(x) - 1; i >= 0; i-- {
		out[i] = f.fpMul(prefix[i], suffix)
		if i > 0 {
			suffix = f.fpMul(suffix, x[i])
		}
	}
	return out
}

func (f *parameters) fp2Norm(x fp2) fp            { return f.fpAdd(f.fpSqr(x.re), f.fpSqr(x.im)) }
func (f *parameters) fp2ZeroChoice(x fp2) int     { return int(x.re.IsZero() & x.im.IsZero()) }
func (f *parameters) fp2EqualChoice(x, y fp2) int { return int(x.re.Equal(y.re) & x.im.Equal(y.im)) }
func (f *parameters) fp2Half(x fp2) fp2           { return fp2{f.fpHalf(x.re), f.fpHalf(x.im)} }
func (f *parameters) fp2IsSquare(x fp2) bool      { return f.fpIsSquare(f.fp2Norm(x)) }

// fp2Sqrt follows fp2_sqrt in gf/ref/lvlx/fp2.c, including its canonical
// sign: the first nonzero component is even. Exponentiation uses bigmod.
func (f *parameters) fp2Sqrt(x fp2) (fp2, bool) {
	x0 := f.fpExp(f.fp2Norm(x), f.sqrtExponent)
	x0 = f.fpSelect(x0, x.re, int(x.im.IsZero()))
	x0 = f.fpAdd(x0, x.re)
	t0 := f.fpAdd(x0, x0)
	x1 := f.fpExp(t0, f.progenitorExponent)
	x0, x1 = f.fpMul(x0, x1), f.fpMul(x1, x.im)
	t1 := f.fpSqr(f.fpAdd(x0, x0))
	choice := int(f.fpSub(t0, t1).IsZero())
	re := f.fpSelect(x1, x0, choice)
	im := f.fpSelect(f.fpNeg(x0), x1, choice)
	negate := int(re.IsOdd() | (re.IsZero() & im.IsOdd()))
	out := fp2{f.fpSelect(re, f.fpNeg(re), negate), f.fpSelect(im, f.fpNeg(im), negate)}
	return out, f.fp2EqualChoice(f.fp2Sqr(out), x) == 1
}
