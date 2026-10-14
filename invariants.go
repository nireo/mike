// SPDX-License-Identifier: Apache-2.0

package mike

// relativeInvariants follows weil/ref/lvlx/invariants.c and computes
// 2*I1/I0,...,2*I9/I0. Inversion uses the same fixed exponent when I0 is
// zero: like C, fpInv(0) gives zero and exchange rejects the all-zero result.
func (f *parameters) relativeInvariants(theta weilPoint) [9]fp {
	t0, t1 := f.fpAdd(theta[0], theta[5]), f.fpSub(theta[0], theta[5])
	t2, t3 := f.fpAdd(theta[7], theta[9]), f.fpSub(theta[7], theta[9])
	u0, u2 := f.fpAdd(t0, t2), f.fpSub(t0, t2)
	u1, u3 := f.fpAdd(t1, t3), f.fpSub(t1, t3)
	i0 := f.fpSqr(u0)
	var rel [9]fp
	rel[0], rel[1], rel[2] = f.fpSqr(u1), f.fpSqr(u2), f.fpSqr(u3)
	u0 = f.fpMul(theta[3], theta[4])
	for i := 0; i < 4; i++ {
		u0 = f.fpAdd(u0, u0)
	}
	t0, t1 = f.fpAdd(i0, rel[0]), f.fpSub(i0, rel[0])
	t2, t3 = f.fpAdd(rel[1], rel[2]), f.fpSub(rel[1], rel[2])
	u2, u1, u3 = f.fpSub(t0, t2), f.fpAdd(t1, t3), f.fpSub(t1, t3)
	rel[3], rel[4] = f.fpAdd(u1, u0), f.fpSub(u1, u0)
	rel[5], rel[6] = f.fpAdd(u2, u0), f.fpSub(u2, u0)
	rel[7], rel[8] = f.fpAdd(u3, u0), f.fpSub(u3, u0)
	i0 = f.fpInv(i0)
	for i := range rel {
		rel[i] = f.fpMul(rel[i], i0)
	}
	for i := 0; i < 3; i++ {
		rel[i] = f.fpAdd(rel[i], rel[i])
	}
	return rel
}

func (f *parameters) mikeAbsoluteInvariants(theta weilPoint) [4]fp {
	rel := f.relativeInvariants(theta)
	out := [4]fp{f.fpSmall(0), f.fpSmall(0), f.fpSmall(0), f.fpSmall(0)}
	for _, x := range rel {
		x2 := f.fpSqr(x)
		x3 := f.fpMul(x, x2)
		x4 := f.fpSqr(x2)
		x5 := f.fpMul(x, x4)
		out[0] = f.fpAdd(out[0], x2)
		out[1] = f.fpAdd(out[1], x3)
		out[2] = f.fpAdd(out[2], x4)
		out[3] = f.fpAdd(out[3], x5)
	}
	return out
}
