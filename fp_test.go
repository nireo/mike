package mike

import (
	"bytes"
	"math/big"
	"slices"
	"testing"
)

func TestPrimeFieldAgainstBigInt(t *testing.T) {
	p := new(big.Int).SetBytes(primeBytes)
	if p.BitLen() != 318 || !p.ProbablyPrime(32) {
		t.Fatal("incorrect p308_633 modulus")
	}
	values := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2),
		new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(p, big.NewInt(2))}
	for _, x := range values {
		for _, y := range values {
			xBytes, yBytes := x.FillBytes(make([]byte, FieldElementSize)), y.FillBytes(make([]byte, FieldElementSize))
			// The field decoder takes little-endian bytes.
			xLE, yLE := slices.Clone(xBytes), slices.Clone(yBytes)
			slices.Reverse(xLE)
			slices.Reverse(yLE)
			xf, err := fpDecode(xLE)
			if err != nil {
				t.Fatal(err)
			}
			yf, err := fpDecode(yLE)
			if err != nil {
				t.Fatal(err)
			}
			for _, op := range []struct {
				name string
				got  fp
				want *big.Int
			}{
				{"add", fpAdd(xf, yf), new(big.Int).Add(x, y)},
				{"sub", fpSub(xf, yf), new(big.Int).Sub(x, y)},
				{"mul", fpMul(xf, yf), new(big.Int).Mul(x, y)},
			} {
				op.want.Mod(op.want, p)
				if new(big.Int).SetBytes(op.got.Bytes(prime)).Cmp(op.want) != 0 {
					t.Fatalf("%s(%s, %s) mismatch", op.name, x, y)
				}
			}
			if !bytes.Equal(xf.Bytes(prime), xBytes) || !bytes.Equal(yf.Bytes(prime), yBytes) {
				t.Fatal("operation mutated its inputs")
			}
			for choice := 0; choice < 2; choice++ {
				want := xBytes
				if choice == 1 {
					want = yBytes
				}
				if !bytes.Equal(fpSelect(xf, yf, choice).Bytes(prime), want) {
					t.Fatal("select mismatch")
				}
			}
		}
	}
}

func TestExtensionField(t *testing.T) {
	x, y := fp2{fpSmall(1), fpSmall(2)}, fp2{fpSmall(3), fpSmall(4)}
	product := fp2Mul(x, y)
	if product.re.Equal(fpNeg(fpSmall(5))) != 1 || product.im.Equal(fpSmall(10)) != 1 {
		t.Fatal("Fp2 multiplication mismatch")
	}
	square := fp2Sqr(x)
	if square.re.Equal(fpNeg(fpSmall(3))) != 1 || square.im.Equal(fpSmall(4)) != 1 {
		t.Fatal("Fp2 square mismatch")
	}
	one := fp2Mul(x, fp2Inv(x))
	if one.re.IsOne() != 1 || one.im.IsZero() != 1 {
		t.Fatal("Fp2 inversion mismatch")
	}
	if !fp2IsZero(fp2Inv(fp2Small(0))) {
		t.Fatal("inverse of zero must match C's zero result")
	}
	if x.re.Equal(fpSmall(1)) != 1 || x.im.Equal(fpSmall(2)) != 1 {
		t.Fatal("operation mutated its inputs")
	}
}

func TestNormalizationOrdering(t *testing.T) {
	one, two, i := fp2Small(1), fp2Small(2), fp2{fpSmall(0), fpSmall(1)}
	if ecFP2LessThan(one, two) != 1 || ecFP2LessThan(two, one) != 0 || ecFP2LessThan(one, one) != 0 {
		t.Fatal("real component ordering mismatch")
	}
	if ecFP2LessThan(two, i) != 1 || ecFP2LessThan(i, two) != 0 {
		t.Fatal("imaginary component should be most significant")
	}
	if _, ok := ecNormalizeMontgomery(ecPoint{fp2Small(1), fp2Small(1)}); ok {
		t.Fatal("accepted zero denominator")
	}
}
