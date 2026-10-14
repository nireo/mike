// SPDX-License-Identifier: Apache-2.0

package mike

import (
	"crypto/subtle"
	"encoding/hex"
	"math/bits"

	"github.com/nireo/mike/internal/bigmod"
)

// Prime-field arithmetic is delegated to the upstream bigmod implementation.
// These wrappers keep the C formulas readable. Fixed-size values own their
// limbs in Montgomery form, so results can live on the stack and copying a
// point never aliases mutable storage. Nat views borrow that storage only
// during an operation; conversion happens at encoding and exponentiation.
const limbBytes = bits.UintSize / 8
const maxFieldLimbs = (maxPublicKeySize / 2) / limbBytes

type fp struct {
	limbs [maxFieldLimbs]uint
	n     int // Public modulus size, never derived from the field value.
}

func (x *fp) nat() bigmod.Nat { return bigmod.NewNatWithStorage(x.limbs[:x.n]) }

func (x fp) IsZero() uint { n := x.nat(); return n.IsZero() }
func (x fp) Equal(y fp) uint {
	xn, yn := x.nat(), y.nat()
	return xn.Equal(&yn)
}

func (x fp) Bytes(m *bigmod.Modulus) []byte {
	n := x.nat()
	n.FromMontgomery(m)
	return n.Bytes(m)
}

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

func (f *parameters) fpSmall(x uint) fp {
	// x is a public constant or a public basis-search candidate, never a
	// secret-derived field value. Cache the common constants 0 through 3.
	if x < uint(len(f.small)) {
		return f.small[x]
	}
	z := fp{n: f.limbCount}
	z.limbs[0] = x
	zn := z.nat()
	zn.ToMontgomery(f.prime)
	return z
}

func (f *parameters) fpIsOne(x fp) uint { return x.Equal(f.small[1]) }
func (f *parameters) fpIsOdd(x fp) uint {
	xn := x.nat()
	xn.FromMontgomery(f.prime)
	return xn.IsOdd()
}

func (f *parameters) fpAdd(x, y fp) fp {
	xn, yn := x.nat(), y.nat()
	xn.Add(&yn, f.prime)
	return x
}

func (f *parameters) fpSub(x, y fp) fp {
	xn, yn := x.nat(), y.nat()
	xn.Sub(&yn, f.prime)
	return x
}

func (f *parameters) fpNeg(x fp) fp { return f.fpSub(f.fpSmall(0), x) }
func (f *parameters) fpMul(x, y fp) fp {
	xn, yn := x.nat(), y.nat()
	xn.MulMontgomery(&yn, f.prime)
	return x
}
func (f *parameters) fpSqr(x fp) fp { return f.fpMul(x, x) }
func (f *parameters) fpInv(x fp) fp { return f.fpExp(x, f.inverseExponent) }

// fpSelect selects x for choice=0 or y for choice=1 using the stdlib primitive.
func (f *parameters) fpSelect(x, y fp, choice int) fp {
	z := fp{n: f.limbCount}
	for i := 0; i < z.n; i++ {
		z.limbs[i] = uint(subtle.ConstantTimeSelect(choice, int(y.limbs[i]), int(x.limbs[i])))
	}
	return z
}

// fpEncodingCanonical returns 1 for an encoding strictly below p. For the
// public field length, the subtraction visits every byte even on invalid input.
func (f *parameters) fpEncodingCanonical(b []byte) int {
	if len(b) != f.fieldBytes {
		return 0
	}
	var borrow uint16
	for i, value := range b {
		difference := uint16(value) - uint16(f.primeLE[i]) - borrow
		borrow = difference >> 15
	}
	return int(borrow)
}

func (f *parameters) fpDecode(b []byte) (fp, error) {
	if len(b) != f.fieldBytes {
		return fp{}, ErrPublicKey
	}
	var be [maxPublicKeySize / 2]byte
	for i := range b {
		be[len(b)-1-i] = b[i]
	}
	x := f.fpSmall(0)
	xn := x.nat()
	if _, err := xn.SetBytes(be[:len(b)], f.prime); err != nil {
		return fp{}, err
	}
	xn.ToMontgomery(f.prime)
	return x, nil
}

func (f *parameters) fpEncode(b []byte, x fp) {
	xn := x.nat()
	xn.FromMontgomery(f.prime)
	for i := 0; i < f.fieldBytes; i++ {
		b[i] = byte(x.limbs[i/limbBytes] >> (8 * (i % limbBytes)))
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
