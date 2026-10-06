// SPDX-License-Identifier: Apache-2.0

package mike

import (
	"crypto/subtle"
	"encoding/hex"
	"slices"

	"github.com/nireo/mike/internal/bigmod"
)

// Prime-field arithmetic is delegated to the upstream bigmod implementation.
// These wrappers keep the C formulas readable. Values are immutable: every
// operation returns a fresh Nat, so copying a point never aliases mutable limbs.
type fp = *bigmod.Nat

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

// new(Nat) lets bigmod allocate only the limbs needed for this modulus;
// NewNat preallocates 2048 bits for RSA, which wastes space for MIKE.
func (f *parameters) fpSmall(x uint) fp { return new(bigmod.Nat).SetUint(x).ExpandFor(f.prime) }

func (f *parameters) fpCopy(x fp) fp {
	z := new(bigmod.Nat).ExpandFor(f.prime)
	copy(z.Bits(), x.Bits())
	return z
}

func (f *parameters) fpAdd(x, y fp) fp { return f.fpCopy(x).Add(y, f.prime) }
func (f *parameters) fpSub(x, y fp) fp { return f.fpCopy(x).Sub(y, f.prime) }
func (f *parameters) fpNeg(x fp) fp    { return f.fpSmall(0).Sub(x, f.prime) }
func (f *parameters) fpMul(x, y fp) fp { return f.fpCopy(x).Mul(y, f.prime) }
func (f *parameters) fpSqr(x fp) fp    { return f.fpMul(x, x) }
func (f *parameters) fpInv(x fp) fp    { return new(bigmod.Nat).Exp(x, f.inverseExponent, f.prime) }

// fpSelect selects x for choice=0 or y for choice=1 using the stdlib primitive.
func (f *parameters) fpSelect(x, y fp, choice int) fp {
	z := new(bigmod.Nat).ExpandFor(f.prime)
	for i := range z.Bits() {
		z.Bits()[i] = uint(subtle.ConstantTimeSelect(choice, int(y.Bits()[i]), int(x.Bits()[i])))
	}
	return z
}

func (f *parameters) fpDecode(b []byte) (fp, error) {
	be := slices.Clone(b)
	slices.Reverse(be)
	return new(bigmod.Nat).SetBytes(be, f.prime)
}

func (f *parameters) fpEncode(b []byte, x fp) {
	be := x.Bytes(f.prime)
	for i := range be {
		b[i] = be[len(be)-1-i]
	}
}

// Fp2 formulas below map to mike_c/src/gf/ref/lvlx/fp2.c (i^2 = -1).
type fp2 struct{ re, im fp }

func (f *parameters) fp2Small(x uint) fp2 { return fp2{f.fpSmall(x), f.fpSmall(0)} }
func (f *parameters) fp2Add(x, y fp2) fp2 { return fp2{f.fpAdd(x.re, y.re), f.fpAdd(x.im, y.im)} }
func (f *parameters) fp2Sub(x, y fp2) fp2 { return fp2{f.fpSub(x.re, y.re), f.fpSub(x.im, y.im)} }
func (f *parameters) fp2Neg(x fp2) fp2    { return fp2{f.fpNeg(x.re), f.fpNeg(x.im)} }

func (f *parameters) fp2Mul(x, y fp2) fp2 {
	t0 := f.fpMul(f.fpAdd(x.re, x.im), f.fpAdd(y.re, y.im))
	t1 := f.fpMul(x.im, y.im)
	re := f.fpMul(x.re, y.re)
	return fp2{f.fpSub(re, t1), f.fpSub(f.fpSub(t0, t1), re)}
}

func (f *parameters) fp2Sqr(x fp2) fp2 {
	sum, diff := f.fpAdd(x.re, x.im), f.fpSub(x.re, x.im)
	im := f.fpMul(x.re, x.im)
	return fp2{f.fpMul(sum, diff), f.fpAdd(im, im)}
}

func (f *parameters) fp2Inv(x fp2) fp2 {
	t := f.fpInv(f.fpAdd(f.fpSqr(x.re), f.fpSqr(x.im)))
	return fp2{f.fpMul(x.re, t), f.fpNeg(f.fpMul(x.im, t))}
}

func (f *parameters) fp2IsZero(x fp2) bool { return x.re.IsZero()&x.im.IsZero() == 1 }
func (f *parameters) fp2MulByI(x fp2) fp2  { return fp2{f.fpNeg(x.im), x.re} }
func (f *parameters) fp2Frob(x fp2) fp2    { return fp2{x.re, f.fpNeg(x.im)} }
func (f *parameters) fp2Select(x, y fp2, choice int) fp2 {
	return fp2{f.fpSelect(x.re, y.re, choice), f.fpSelect(x.im, y.im, choice)}
}

func (f *parameters) fp2Encode(b []byte, x fp2) {
	f.fpEncode(b[:f.fieldBytes], x.re)
	f.fpEncode(b[f.fieldBytes:], x.im)
}
