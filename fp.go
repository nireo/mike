// SPDX-License-Identifier: Apache-2.0

package mike

import (
	"crypto/subtle"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/nireo/mike/internal/bigmod"
)

// Prime-field arithmetic is delegated to the upstream bigmod implementation.
// These wrappers keep the C formulas readable. Values are immutable: every
// operation returns a fresh Nat, so copying a point never aliases mutable limbs.
type fp = *bigmod.Nat

var (
	primeBytes      = mustHex("278f" + strings.Repeat("ff", 38)) // 633*2^308 - 1
	prime           = mustModulus(primeBytes)
	inverseExponent = func() []byte {
		e := slices.Clone(primeBytes)
		e[len(e)-1] -= 2
		return e
	}()
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func mustModulus(b []byte) *bigmod.Modulus {
	m, err := bigmod.NewModulus(b)
	if err != nil {
		panic(err)
	}
	return m
}

// new(Nat) lets bigmod allocate only the five (or ten on 32-bit) limbs needed
// here; NewNat preallocates 2048 bits for RSA, which wastes space for MIKE.
func fpSmall(x uint) fp { return new(bigmod.Nat).SetUint(x).ExpandFor(prime) }

func fpCopy(x fp) fp {
	z := new(bigmod.Nat).ExpandFor(prime)
	copy(z.Bits(), x.Bits())
	return z
}

func fpAdd(x, y fp) fp { return fpCopy(x).Add(y, prime) }
func fpSub(x, y fp) fp { return fpCopy(x).Sub(y, prime) }
func fpNeg(x fp) fp    { return fpSmall(0).Sub(x, prime) }
func fpMul(x, y fp) fp { return fpCopy(x).Mul(y, prime) }
func fpSqr(x fp) fp    { return fpMul(x, x) }
func fpInv(x fp) fp    { return new(bigmod.Nat).Exp(x, inverseExponent, prime) }

// fpSelect selects x for choice=0 or y for choice=1 using the stdlib primitive.
func fpSelect(x, y fp, choice int) fp {
	z := new(bigmod.Nat).ExpandFor(prime)
	for i := range z.Bits() {
		z.Bits()[i] = uint(subtle.ConstantTimeSelect(choice, int(y.Bits()[i]), int(x.Bits()[i])))
	}
	return z
}

func fpDecode(b []byte) (fp, error) {
	be := slices.Clone(b)
	slices.Reverse(be)
	return new(bigmod.Nat).SetBytes(be, prime)
}

func fpEncode(b []byte, x fp) {
	be := x.Bytes(prime)
	for i := range be {
		b[i] = be[len(be)-1-i]
	}
}

// Fp2 formulas below map to mike_c/src/gf/ref/lvlx/fp2.c (i^2 = -1).
type fp2 struct{ re, im fp }

func fp2Small(x uint) fp2 { return fp2{fpSmall(x), fpSmall(0)} }
func fp2Add(x, y fp2) fp2 { return fp2{fpAdd(x.re, y.re), fpAdd(x.im, y.im)} }
func fp2Sub(x, y fp2) fp2 { return fp2{fpSub(x.re, y.re), fpSub(x.im, y.im)} }
func fp2Neg(x fp2) fp2    { return fp2{fpNeg(x.re), fpNeg(x.im)} }

func fp2Mul(x, y fp2) fp2 {
	t0 := fpMul(fpAdd(x.re, x.im), fpAdd(y.re, y.im))
	t1 := fpMul(x.im, y.im)
	re := fpMul(x.re, y.re)
	return fp2{fpSub(re, t1), fpSub(fpSub(t0, t1), re)}
}

func fp2Sqr(x fp2) fp2 {
	sum, diff := fpAdd(x.re, x.im), fpSub(x.re, x.im)
	im := fpMul(x.re, x.im)
	return fp2{fpMul(sum, diff), fpAdd(im, im)}
}

func fp2Inv(x fp2) fp2 {
	t := fpInv(fpAdd(fpSqr(x.re), fpSqr(x.im)))
	return fp2{fpMul(x.re, t), fpNeg(fpMul(x.im, t))}
}

func fp2IsZero(x fp2) bool { return x.re.IsZero()&x.im.IsZero() == 1 }
func fp2MulByI(x fp2) fp2  { return fp2{fpNeg(x.im), x.re} }
func fp2Frob(x fp2) fp2    { return fp2{x.re, fpNeg(x.im)} }
func fp2Select(x, y fp2, choice int) fp2 {
	return fp2{fpSelect(x.re, y.re, choice), fpSelect(x.im, y.im, choice)}
}

func fp2Encode(b []byte, x fp2) {
	fpEncode(b[:FieldElementSize], x.re)
	fpEncode(b[FieldElementSize:], x.im)
}
