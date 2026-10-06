// SPDX-License-Identifier: Apache-2.0

package mike

// relativeInvariants follows weil/ref/lvlx/invariants.c and computes
// 2*I1/I0,...,2*I9/I0. No division is performed when I0 is zero: like C,
// fpInv(0) gives zero, which the exchange rejects as an all-zero result.
func relativeInvariants(theta weilPoint) [9]fp {
	t0, t1 := fpAdd(theta[0], theta[5]), fpSub(theta[0], theta[5])
	t2, t3 := fpAdd(theta[7], theta[9]), fpSub(theta[7], theta[9])
	u0, u2 := fpAdd(t0, t2), fpSub(t0, t2)
	u1, u3 := fpAdd(t1, t3), fpSub(t1, t3)
	i0 := fpSqr(u0)
	var rel [9]fp
	rel[0], rel[1], rel[2] = fpSqr(u1), fpSqr(u2), fpSqr(u3)
	u0 = fpMul(theta[3], theta[4])
	for i := 0; i < 4; i++ {
		u0 = fpAdd(u0, u0)
	}
	t0, t1 = fpAdd(i0, rel[0]), fpSub(i0, rel[0])
	t2, t3 = fpAdd(rel[1], rel[2]), fpSub(rel[1], rel[2])
	u2, u1, u3 = fpSub(t0, t2), fpAdd(t1, t3), fpSub(t1, t3)
	rel[3], rel[4] = fpAdd(u1, u0), fpSub(u1, u0)
	rel[5], rel[6] = fpAdd(u2, u0), fpSub(u2, u0)
	rel[7], rel[8] = fpAdd(u3, u0), fpSub(u3, u0)
	i0 = fpInv(i0)
	for i := range rel {
		rel[i] = fpMul(rel[i], i0)
	}
	for i := 0; i < 3; i++ {
		rel[i] = fpAdd(rel[i], rel[i])
	}
	return rel
}

func mikeAbsoluteInvariants(theta weilPoint) [4]fp {
	rel := relativeInvariants(theta)
	out := [4]fp{fpSmall(0), fpSmall(0), fpSmall(0), fpSmall(0)}
	for _, x := range rel {
		x2 := fpSqr(x)
		x3 := fpMul(x, x2)
		x4 := fpSqr(x2)
		x5 := fpMul(x, x4)
		out[0] = fpAdd(out[0], x2)
		out[1] = fpAdd(out[1], x3)
		out[2] = fpAdd(out[2], x4)
		out[3] = fpAdd(out[3], x5)
	}
	return out
}
