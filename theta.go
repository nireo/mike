// SPDX-License-Identifier: Apache-2.0

package mike

// Theta coordinates follow theta/ref/include/theta.h. Immutable field values
// let arrays be copied directly, including when a formula overwrites its input.
type theta2 [4]fp
type theta4 [16]fp
type weilPoint [10]fp
type theta2Struct struct{ invDual, dual theta2 }
type theta2Precomp struct{ invNull, invHSNull theta2 }
type weilPrecomp struct{ invNull, invHSNull weilPoint }

var thetaToWeil = [16]int{0, 1, 2, 3, 2, 4, 5, 6, 1, 7, 4, 8, 3, 8, 6, 9}
var weilToTheta = [10]int{0, 1, 2, 3, 5, 6, 7, 9, 11, 15}

// Hadamard butterflies are the same four stages as theta_hadamard_dim4 in C.
func thetaHadamard(in []fp) []fp {
	out := append([]fp(nil), in...)
	for step := 1; step < len(out); step *= 2 {
		for base := 0; base < len(out); base += 2 * step {
			for i := 0; i < step; i++ {
				x, y := out[base+i], out[base+i+step]
				out[base+i], out[base+i+step] = fpAdd(x, y), fpSub(x, y)
			}
		}
	}
	return out
}
func thetaH2(x theta2) theta2 { return theta2(thetaHadamard(x[:])) }
func thetaH4(x theta4) theta4 { return theta4(thetaHadamard(x[:])) }
func thetaExpand(x weilPoint) theta4 {
	var out theta4
	for i := range out {
		out[i] = x[thetaToWeil[i]]
	}
	return out
}
func thetaCompress(x theta4) weilPoint {
	var out weilPoint
	for i := range out {
		out[i] = x[weilToTheta[i]]
	}
	return out
}
func thetaHWeil(x weilPoint) weilPoint { return thetaCompress(thetaH4(thetaExpand(x))) }
func thetaSqr2(x theta2) theta2 {
	for i := range x {
		x[i] = fpSqr(x[i])
	}
	return x
}
func thetaSqr4(x theta4) theta4 {
	for i := range x {
		x[i] = fpSqr(x[i])
	}
	return x
}
func thetaSqrWeil(x weilPoint) weilPoint {
	for i := range x {
		x[i] = fpSqr(x[i])
	}
	return x
}
func thetaDot2(x, y theta2) theta2 {
	for i := range x {
		x[i] = fpMul(x[i], y[i])
	}
	return x
}
func thetaDot4(x, y theta4) theta4 {
	for i := range x {
		x[i] = fpMul(x[i], y[i])
	}
	return x
}
func thetaDotWeil(x theta4, y weilPoint) theta4 {
	for i := range x {
		x[i] = fpMul(x[i], y[thetaToWeil[i]])
	}
	return x
}
func thetaInv2(x theta2) theta2          { return theta2(fpProjectiveInverse(x[:])) }
func thetaInvWeil(x weilPoint) weilPoint { return weilPoint(fpProjectiveInverse(x[:])) }

// Dimension-2 routines map to isogeny_dim2.c and theta_struct_dim2.c.
func thetaIsogeny2Compute(ker [2]theta2) theta2Struct {
	h0, h1 := thetaH2(thetaSqr2(ker[0])), thetaH2(thetaSqr2(ker[1]))
	t1, t2 := fpMul(h0[0], h1[1]), fpMul(h0[1], h1[0])
	dual := theta2{fpMul(h1[0], t1), fpMul(h1[1], t2), fpMul(h1[2], t1), fpMul(h1[3], t2)}
	t3 := fpMul(h1[2], h1[3])
	return theta2Struct{theta2{fpMul(t3, h0[1]), fpMul(t3, h0[0]), dual[3], dual[2]}, dual}
}
func thetaIsogeny2Eval(p theta2, s theta2Struct) theta2 {
	return thetaDot2(thetaH2(thetaSqr2(p)), s.invDual)
}
func thetaPrecompute2(s theta2Struct) theta2Precomp {
	return theta2Precomp{s.invDual, thetaInv2(thetaH2(thetaSqr2(s.dual)))}
}
func thetaDiffAdd2(p, q, invPmQ theta2, pre theta2Precomp) theta2 {
	p = thetaDot2(thetaH2(thetaSqr2(p)), thetaH2(thetaSqr2(q)))
	p = thetaDot2(p, pre.invHSNull)
	return thetaDot2(thetaH2(p), invPmQ)
}

// solveHIIPWeil maps to solve_HIIP_weil in isogeny_dim4.c.
func solveHIIPWeil(h [2]theta4) weilPoint {
	var red, blue [8]fp
	red[0] = h[0][12]
	red[1] = fpMul(red[0], h[0][5])
	red[2] = fpMul(red[1], h[1][1])
	red[3] = fpMul(red[2], h[0][9])
	red[4] = fpMul(red[3], h[0][11])
	red[5] = fpMul(red[4], h[1][15])
	red[6] = fpMul(red[5], h[1][14])
	red[7] = fpMul(red[6], h[0][6])
	blue[7] = h[0][0]
	blue[6] = fpMul(blue[7], h[0][2])
	blue[5] = fpMul(blue[6], h[1][6])
	blue[4] = fpMul(blue[5], h[1][7])
	blue[3] = fpMul(blue[4], h[0][15])
	blue[2] = fpMul(blue[3], h[0][13])
	blue[1] = fpMul(blue[2], h[1][9])
	blue[0] = fpMul(blue[1], h[0][1])
	var out weilPoint
	out[0] = fpMul(red[7], h[0][4])
	out[3] = fpMul(fpMul(h[0][8], h[0][5]), blue[1])
	indices := [8]int{4, 1, 7, 8, 9, 6, 5, 2}
	for i, j := range indices {
		out[j] = fpMul(red[i], blue[i])
	}
	return out
}
func thetaIsogenyWeilCompute(ker [2]theta4, dual bool) weilPoint {
	for i := range ker {
		if dual {
			ker[i] = thetaH4(ker[i])
		}
		ker[i] = thetaH4(thetaSqr4(ker[i]))
	}
	return solveHIIPWeil(ker)
}
func thetaIsogenyWeilEval(p theta4, invDual weilPoint, dual bool) theta4 {
	if dual {
		p = thetaH4(p)
	}
	return thetaDotWeil(thetaH4(thetaSqr4(p)), invDual)
}
func thetaPrecomputeWeil(invDual weilPoint) weilPrecomp {
	return weilPrecomp{invDual, thetaInvWeil(thetaHWeil(thetaSqrWeil(thetaInvWeil(invDual))))}
}
func thetaDblWeil(p theta4, pre weilPrecomp) theta4 {
	p = thetaSqr4(thetaH4(thetaSqr4(p)))
	p = thetaDotWeil(p, pre.invHSNull)
	return thetaDotWeil(thetaH4(p), pre.invNull)
}
func thetaDblIterWeil(p theta4, pre weilPrecomp, n int) theta4 {
	for i := 0; i < n; i++ {
		p = thetaDblWeil(p, pre)
	}
	return p
}

// isogeny_chain_weil's balanced split strategy, retaining its normal/dual
// transition after the first step. p308_633 requires a 225-step chain.
func isogenyChainWeil(invDual weilPoint, pre weilPrecomp, t3, t4 theta4) weilPoint {
	const length = secretKeyChainLength - 3
	var ker [9][2]theta4
	var orders [9]int
	ker[0], orders[0] = [2]theta4{t3, t4}, length
	current, step := 0, 0
	for current >= 0 {
		firstDouble := true
		for orders[current] != 1 {
			if firstDouble && step != 0 {
				pre = thetaPrecomputeWeil(invDual)
			}
			firstDouble = false
			current++
			n := orders[current-1] / 2
			ker[current] = [2]theta4{
				thetaDblIterWeil(ker[current-1][0], pre, n),
				thetaDblIterWeil(ker[current-1][1], pre, n),
			}
			orders[current] = orders[current-1] - n
		}
		invDual = thetaIsogenyWeilCompute(ker[current], step != 0)
		for j := 0; j < current; j++ {
			ker[j][0] = thetaIsogenyWeilEval(ker[j][0], invDual, step != 0)
			ker[j][1] = thetaIsogenyWeilEval(ker[j][1], invDual, step != 0)
			orders[j]--
		}
		current--
		step++
	}
	return invDual
}
