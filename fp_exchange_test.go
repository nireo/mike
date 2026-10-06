package mike

import "testing"

func TestExtensionSquareRoots(t *testing.T) {
	for _, tc := range []struct{ input, want fp2 }{
		{fp2Small(0), fp2Small(0)},
		{fp2Small(1), fp2{fpNeg(fpSmall(1)), fpSmall(0)}},
		{fp2{fpNeg(fpSmall(1)), fpSmall(0)}, fp2{fpSmall(0), fpNeg(fpSmall(1))}},
		{fp2{fpSmall(3), fpSmall(4)}, fp2{fpSmall(2), fpSmall(1)}},
		{fp2{fpSmall(24), fpSmall(10)}, fp2{fpNeg(fpSmall(5)), fpNeg(fpSmall(1))}},
	} {
		got, ok := fp2Sqrt(tc.input)
		if !ok || fp2EqualChoice(got, tc.want) != 1 {
			t.Fatal("incorrect canonical square root")
		}
	}
	// The norm is 5, a nonresidue for this prime (p mod 5 = 2).
	if _, ok := fp2Sqrt(fp2{fpSmall(1), fpSmall(2)}); ok {
		t.Fatal("accepted a nonsquare")
	}
	if fpHalf(fpSmall(2)).IsOne() != 1 {
		t.Fatal("incorrect inverse of two")
	}
}

func TestProjectiveInverseWithZeros(t *testing.T) {
	for _, tc := range []struct{ input, want [3]uint }{
		{[3]uint{2, 3, 5}, [3]uint{15, 10, 6}},
		{[3]uint{0, 3, 5}, [3]uint{15, 0, 0}},
		{[3]uint{0, 0, 5}, [3]uint{0, 0, 0}},
	} {
		x := []fp{fpSmall(tc.input[0]), fpSmall(tc.input[1]), fpSmall(tc.input[2])}
		inverse := fpProjectiveInverse(x)
		for i := range x {
			if inverse[i].Equal(fpSmall(tc.want[i])) != 1 {
				t.Fatal("incorrect projective inverse")
			}
			if x[i].Equal(fpSmall(tc.input[i])) != 1 {
				t.Fatal("projective inverse mutated its input")
			}
		}
	}
}

func TestThetaHadamardInvolution(t *testing.T) {
	for _, size := range []int{4, 16} {
		x := make([]fp, size)
		for i := range x {
			x[i] = fpSmall(uint(i))
		}
		got := thetaHadamard(thetaHadamard(x))
		for i := range got {
			if got[i].Equal(fpSmall(uint(size*i))) != 1 {
				t.Fatal("incorrect Hadamard scaling")
			}
		}
	}
	var x weilPoint
	for i := range x {
		x[i] = fpSmall(uint(i))
	}
	got := thetaHWeil(thetaHWeil(x))
	for i := range got {
		if got[i].Equal(fpSmall(uint(16*i))) != 1 {
			t.Fatal("incorrect compressed Hadamard scaling")
		}
	}
}
