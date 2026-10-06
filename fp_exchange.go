// SPDX-License-Identifier: Apache-2.0

package mike

import (
	"strings"

	"github.com/nireo/mike/internal/bigmod"
)

var (
	sqrtExponent       = mustHex("09e4" + strings.Repeat("00", 38)) // (p+1)/4
	progenitorExponent = mustHex("09e3" + strings.Repeat("ff", 38)) // (p-3)/4
	legendreExponent   = mustHex("13c7" + strings.Repeat("ff", 38)) // (p-1)/2
	inverseTwo         = mustFP("00" + strings.Repeat("00", 37) + "c813")
)

func fpExp(x fp, exponent []byte) fp { return new(bigmod.Nat).Exp(x, exponent, prime) }
func fpHalf(x fp) fp                 { return fpMul(x, inverseTwo) }
func fpIsSquare(x fp) bool {
	return fpExp(x, legendreExponent).IsOne()|x.IsZero() == 1
}

// fpProjectiveInverse returns products of all coordinates except the selected
// one, matching fp_proj_batched_inv. This preserves the reference's handling
// of zero coordinates without performing an inversion.
func fpProjectiveInverse(x []fp) []fp {
	prefix := make([]fp, len(x))
	prefix[0] = fpSmall(1)
	for i := 1; i < len(x); i++ {
		prefix[i] = fpMul(prefix[i-1], x[i-1])
	}
	out := make([]fp, len(x))
	suffix := fpSmall(1)
	for i := len(x) - 1; i >= 0; i-- {
		out[i] = fpMul(prefix[i], suffix)
		if i > 0 {
			suffix = fpMul(suffix, x[i])
		}
	}
	return out
}

func fp2Norm(x fp2) fp            { return fpAdd(fpSqr(x.re), fpSqr(x.im)) }
func fp2ZeroChoice(x fp2) int     { return int(x.re.IsZero() & x.im.IsZero()) }
func fp2EqualChoice(x, y fp2) int { return int(x.re.Equal(y.re) & x.im.Equal(y.im)) }
func fp2Half(x fp2) fp2           { return fp2{fpHalf(x.re), fpHalf(x.im)} }
func fp2IsSquare(x fp2) bool      { return fpIsSquare(fp2Norm(x)) }

// fp2Sqrt follows fp2_sqrt in gf/ref/lvlx/fp2.c, including its canonical
// sign: the first nonzero component is even. Exponentiation uses bigmod.
func fp2Sqrt(x fp2) (fp2, bool) {
	x0 := fpExp(fp2Norm(x), sqrtExponent)
	x0 = fpSelect(x0, x.re, int(x.im.IsZero()))
	x0 = fpAdd(x0, x.re)
	t0 := fpAdd(x0, x0)
	x1 := fpExp(t0, progenitorExponent)
	x0, x1 = fpMul(x0, x1), fpMul(x1, x.im)
	t1 := fpSqr(fpAdd(x0, x0))
	choice := int(fpSub(t0, t1).IsZero())
	re := fpSelect(x1, x0, choice)
	im := fpSelect(fpNeg(x0), x1, choice)
	negate := int(re.IsOdd() | (re.IsZero() & im.IsOdd()))
	out := fp2{fpSelect(re, fpNeg(re), negate), fpSelect(im, fpNeg(im), negate)}
	return out, fp2EqualChoice(fp2Sqr(out), x) == 1
}
