package mike

import (
	"bytes"
	"math/big"
	"slices"
	"testing"
)

func TestPrimeFieldAgainstBigInt(t *testing.T) {
	for _, set := range parameterSets {
		t.Run(set.String(), func(t *testing.T) {
			f, err := set.parameters()
			if err != nil {
				t.Fatal(err)
			}
			testPrimeFieldAgainstBigInt(t, f)
		})
	}
}

func testPrimeFieldAgainstBigInt(t *testing.T, f *parameters) {
	p := new(big.Int).SetBytes(f.primeBytes)
	if len(p.Bytes()) != f.fieldBytes || !p.ProbablyPrime(32) {
		t.Fatal("incorrect modulus")
	}
	values := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2),
		new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(p, big.NewInt(2))}
	for _, x := range values {
		for _, y := range values {
			xBytes, yBytes := x.FillBytes(make([]byte, f.fieldBytes)), y.FillBytes(make([]byte, f.fieldBytes))
			// The field decoder takes little-endian bytes.
			xLE, yLE := slices.Clone(xBytes), slices.Clone(yBytes)
			slices.Reverse(xLE)
			slices.Reverse(yLE)
			xf, err := f.fpDecode(xLE)
			if err != nil {
				t.Fatal(err)
			}
			yf, err := f.fpDecode(yLE)
			if err != nil {
				t.Fatal(err)
			}
			for _, op := range []struct {
				name string
				got  fp
				want *big.Int
			}{
				{"add", f.fpAdd(xf, yf), new(big.Int).Add(x, y)},
				{"sub", f.fpSub(xf, yf), new(big.Int).Sub(x, y)},
				{"mul", f.fpMul(xf, yf), new(big.Int).Mul(x, y)},
			} {
				op.want.Mod(op.want, p)
				if new(big.Int).SetBytes(op.got.Bytes(f.prime)).Cmp(op.want) != 0 {
					t.Fatalf("%s(%s, %s) mismatch", op.name, x, y)
				}
			}
			if !bytes.Equal(xf.Bytes(f.prime), xBytes) || !bytes.Equal(yf.Bytes(f.prime), yBytes) {
				t.Fatal("operation mutated its inputs")
			}
			for choice := 0; choice < 2; choice++ {
				want := xBytes
				if choice == 1 {
					want = yBytes
				}
				if !bytes.Equal(f.fpSelect(xf, yf, choice).Bytes(f.prime), want) {
					t.Fatal("select mismatch")
				}
			}
		}
	}
}

func TestExtensionField(t *testing.T) {
	x, y := fp2{defaultParameters.fpSmall(1), defaultParameters.fpSmall(2)}, fp2{defaultParameters.fpSmall(3), defaultParameters.fpSmall(4)}
	product := defaultParameters.fp2Mul(x, y)
	if product.re.Equal(defaultParameters.fpNeg(defaultParameters.fpSmall(5))) != 1 || product.im.Equal(defaultParameters.fpSmall(10)) != 1 {
		t.Fatal("Fp2 multiplication mismatch")
	}
	square := defaultParameters.fp2Sqr(x)
	if square.re.Equal(defaultParameters.fpNeg(defaultParameters.fpSmall(3))) != 1 || square.im.Equal(defaultParameters.fpSmall(4)) != 1 {
		t.Fatal("Fp2 square mismatch")
	}
	one := defaultParameters.fp2Mul(x, defaultParameters.fp2Inv(x))
	if defaultParameters.fpIsOne(one.re) != 1 || one.im.IsZero() != 1 {
		t.Fatal("Fp2 inversion mismatch")
	}
	if !defaultParameters.fp2IsZero(defaultParameters.fp2Inv(defaultParameters.fp2Small(0))) {
		t.Fatal("inverse of zero must match C's zero result")
	}
	if x.re.Equal(defaultParameters.fpSmall(1)) != 1 || x.im.Equal(defaultParameters.fpSmall(2)) != 1 {
		t.Fatal("operation mutated its inputs")
	}
}

func TestNormalizationOrdering(t *testing.T) {
	one, two, i := defaultParameters.fp2Small(1), defaultParameters.fp2Small(2), fp2{defaultParameters.fpSmall(0), defaultParameters.fpSmall(1)}
	if defaultParameters.ecFP2LessThan(one, two) != 1 || defaultParameters.ecFP2LessThan(two, one) != 0 || defaultParameters.ecFP2LessThan(one, one) != 0 {
		t.Fatal("real component ordering mismatch")
	}
	if defaultParameters.ecFP2LessThan(two, i) != 1 || defaultParameters.ecFP2LessThan(i, two) != 0 {
		t.Fatal("imaginary component should be most significant")
	}
	if _, ok := defaultParameters.ecNormalizeMontgomery(ecPoint{defaultParameters.fp2Small(1), defaultParameters.fp2Small(1)}); ok {
		t.Fatal("accepted zero denominator")
	}
}
