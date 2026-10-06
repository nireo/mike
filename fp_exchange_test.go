package mike

import "testing"

func TestExtensionSquareRoots(t *testing.T) {
	for _, tc := range []struct{ input, want fp2 }{
		{defaultParameters.fp2Small(0), defaultParameters.fp2Small(0)},
		{defaultParameters.fp2Small(1), fp2{defaultParameters.fpNeg(defaultParameters.fpSmall(1)), defaultParameters.fpSmall(0)}},
		{fp2{defaultParameters.fpNeg(defaultParameters.fpSmall(1)), defaultParameters.fpSmall(0)}, fp2{defaultParameters.fpSmall(0), defaultParameters.fpNeg(defaultParameters.fpSmall(1))}},
		{fp2{defaultParameters.fpSmall(3), defaultParameters.fpSmall(4)}, fp2{defaultParameters.fpSmall(2), defaultParameters.fpSmall(1)}},
		{fp2{defaultParameters.fpSmall(24), defaultParameters.fpSmall(10)}, fp2{defaultParameters.fpNeg(defaultParameters.fpSmall(5)), defaultParameters.fpNeg(defaultParameters.fpSmall(1))}},
	} {
		got, ok := defaultParameters.fp2Sqrt(tc.input)
		if !ok || defaultParameters.fp2EqualChoice(got, tc.want) != 1 {
			t.Fatal("incorrect canonical square root")
		}
	}
	// The norm is 5, a nonresidue for this prime (p mod 5 = 2).
	if _, ok := defaultParameters.fp2Sqrt(fp2{defaultParameters.fpSmall(1), defaultParameters.fpSmall(2)}); ok {
		t.Fatal("accepted a nonsquare")
	}
	if defaultParameters.fpHalf(defaultParameters.fpSmall(2)).IsOne() != 1 {
		t.Fatal("incorrect inverse of two")
	}
}

func TestProjectiveInverseWithZeros(t *testing.T) {
	for _, tc := range []struct{ input, want [3]uint }{
		{[3]uint{2, 3, 5}, [3]uint{15, 10, 6}},
		{[3]uint{0, 3, 5}, [3]uint{15, 0, 0}},
		{[3]uint{0, 0, 5}, [3]uint{0, 0, 0}},
	} {
		x := []fp{defaultParameters.fpSmall(tc.input[0]), defaultParameters.fpSmall(tc.input[1]), defaultParameters.fpSmall(tc.input[2])}
		inverse := defaultParameters.fpProjectiveInverse(x)
		for i := range x {
			if inverse[i].Equal(defaultParameters.fpSmall(tc.want[i])) != 1 {
				t.Fatal("incorrect projective inverse")
			}
			if x[i].Equal(defaultParameters.fpSmall(tc.input[i])) != 1 {
				t.Fatal("projective inverse mutated its input")
			}
		}
	}
}

func TestThetaHadamardInvolution(t *testing.T) {
	for _, size := range []int{4, 16} {
		x := make([]fp, size)
		for i := range x {
			x[i] = defaultParameters.fpSmall(uint(i))
		}
		got := defaultParameters.thetaHadamard(defaultParameters.thetaHadamard(x))
		for i := range got {
			if got[i].Equal(defaultParameters.fpSmall(uint(size*i))) != 1 {
				t.Fatal("incorrect Hadamard scaling")
			}
		}
	}
	var x weilPoint
	for i := range x {
		x[i] = defaultParameters.fpSmall(uint(i))
	}
	got := defaultParameters.thetaHWeil(defaultParameters.thetaHWeil(x))
	for i := range got {
		if got[i].Equal(defaultParameters.fpSmall(uint(16*i))) != 1 {
			t.Fatal("incorrect compressed Hadamard scaling")
		}
	}
}
