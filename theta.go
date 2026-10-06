// SPDX-License-Identifier: Apache-2.0

package mike

import "math/bits"

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
func (f *parameters) thetaHadamard(in []fp) []fp {
	out := append([]fp(nil), in...)
	for step := 1; step < len(out); step *= 2 {
		for base := 0; base < len(out); base += 2 * step {
			for i := 0; i < step; i++ {
				x, y := out[base+i], out[base+i+step]
				out[base+i], out[base+i+step] = f.fpAdd(x, y), f.fpSub(x, y)
			}
		}
	}
	return out
}
func (f *parameters) thetaH2(x theta2) theta2 { return theta2(f.thetaHadamard(x[:])) }
func (f *parameters) thetaH4(x theta4) theta4 { return theta4(f.thetaHadamard(x[:])) }
func (f *parameters) thetaExpand(x weilPoint) theta4 {
	var out theta4
	for i := range out {
		out[i] = x[thetaToWeil[i]]
	}
	return out
}
func (f *parameters) thetaCompress(x theta4) weilPoint {
	var out weilPoint
	for i := range out {
		out[i] = x[weilToTheta[i]]
	}
	return out
}
func (f *parameters) thetaHWeil(x weilPoint) weilPoint {
	return f.thetaCompress(f.thetaH4(f.thetaExpand(x)))
}
func (f *parameters) thetaSqr2(x theta2) theta2 {
	for i := range x {
		x[i] = f.fpSqr(x[i])
	}
	return x
}
func (f *parameters) thetaSqr4(x theta4) theta4 {
	for i := range x {
		x[i] = f.fpSqr(x[i])
	}
	return x
}
func (f *parameters) thetaSqrWeil(x weilPoint) weilPoint {
	for i := range x {
		x[i] = f.fpSqr(x[i])
	}
	return x
}
func (f *parameters) thetaDot2(x, y theta2) theta2 {
	for i := range x {
		x[i] = f.fpMul(x[i], y[i])
	}
	return x
}
func (f *parameters) thetaDot4(x, y theta4) theta4 {
	for i := range x {
		x[i] = f.fpMul(x[i], y[i])
	}
	return x
}
func (f *parameters) thetaDotWeil(x theta4, y weilPoint) theta4 {
	for i := range x {
		x[i] = f.fpMul(x[i], y[thetaToWeil[i]])
	}
	return x
}
func (f *parameters) thetaInv2(x theta2) theta2 { return theta2(f.fpProjectiveInverse(x[:])) }
func (f *parameters) thetaInvWeil(x weilPoint) weilPoint {
	return weilPoint(f.fpProjectiveInverse(x[:]))
}

// Dimension-2 routines map to isogeny_dim2.c and theta_struct_dim2.c.
func (f *parameters) thetaIsogeny2Compute(ker [2]theta2) theta2Struct {
	h0, h1 := f.thetaH2(f.thetaSqr2(ker[0])), f.thetaH2(f.thetaSqr2(ker[1]))
	t1, t2 := f.fpMul(h0[0], h1[1]), f.fpMul(h0[1], h1[0])
	dual := theta2{f.fpMul(h1[0], t1), f.fpMul(h1[1], t2), f.fpMul(h1[2], t1), f.fpMul(h1[3], t2)}
	t3 := f.fpMul(h1[2], h1[3])
	return theta2Struct{theta2{f.fpMul(t3, h0[1]), f.fpMul(t3, h0[0]), dual[3], dual[2]}, dual}
}
func (f *parameters) thetaIsogeny2Eval(p theta2, s theta2Struct) theta2 {
	return f.thetaDot2(f.thetaH2(f.thetaSqr2(p)), s.invDual)
}
func (f *parameters) thetaPrecompute2(s theta2Struct) theta2Precomp {
	return theta2Precomp{s.invDual, f.thetaInv2(f.thetaH2(f.thetaSqr2(s.dual)))}
}
func (f *parameters) thetaDiffAdd2(p, q, invPmQ theta2, pre theta2Precomp) theta2 {
	p = f.thetaDot2(f.thetaH2(f.thetaSqr2(p)), f.thetaH2(f.thetaSqr2(q)))
	p = f.thetaDot2(p, pre.invHSNull)
	return f.thetaDot2(f.thetaH2(p), invPmQ)
}

// solveHIIPWeil maps to solve_HIIP_weil in isogeny_dim4.c.
func (f *parameters) solveHIIPWeil(h [2]theta4) weilPoint {
	var red, blue [8]fp
	red[0] = h[0][12]
	red[1] = f.fpMul(red[0], h[0][5])
	red[2] = f.fpMul(red[1], h[1][1])
	red[3] = f.fpMul(red[2], h[0][9])
	red[4] = f.fpMul(red[3], h[0][11])
	red[5] = f.fpMul(red[4], h[1][15])
	red[6] = f.fpMul(red[5], h[1][14])
	red[7] = f.fpMul(red[6], h[0][6])
	blue[7] = h[0][0]
	blue[6] = f.fpMul(blue[7], h[0][2])
	blue[5] = f.fpMul(blue[6], h[1][6])
	blue[4] = f.fpMul(blue[5], h[1][7])
	blue[3] = f.fpMul(blue[4], h[0][15])
	blue[2] = f.fpMul(blue[3], h[0][13])
	blue[1] = f.fpMul(blue[2], h[1][9])
	blue[0] = f.fpMul(blue[1], h[0][1])
	var out weilPoint
	out[0] = f.fpMul(red[7], h[0][4])
	out[3] = f.fpMul(f.fpMul(h[0][8], h[0][5]), blue[1])
	indices := [8]int{4, 1, 7, 8, 9, 6, 5, 2}
	for i, j := range indices {
		out[j] = f.fpMul(red[i], blue[i])
	}
	return out
}
func (f *parameters) thetaIsogenyWeilCompute(ker [2]theta4, dual bool) weilPoint {
	for i := range ker {
		if dual {
			ker[i] = f.thetaH4(ker[i])
		}
		ker[i] = f.thetaH4(f.thetaSqr4(ker[i]))
	}
	return f.solveHIIPWeil(ker)
}
func (f *parameters) thetaIsogenyWeilEval(p theta4, invDual weilPoint, dual bool) theta4 {
	if dual {
		p = f.thetaH4(p)
	}
	return f.thetaDotWeil(f.thetaH4(f.thetaSqr4(p)), invDual)
}
func (f *parameters) thetaPrecomputeWeil(invDual weilPoint) weilPrecomp {
	return weilPrecomp{invDual, f.thetaInvWeil(f.thetaHWeil(f.thetaSqrWeil(f.thetaInvWeil(invDual))))}
}
func (f *parameters) thetaDblWeil(p theta4, pre weilPrecomp) theta4 {
	p = f.thetaSqr4(f.thetaH4(f.thetaSqr4(p)))
	p = f.thetaDotWeil(p, pre.invHSNull)
	return f.thetaDotWeil(f.thetaH4(p), pre.invNull)
}
func (f *parameters) thetaDblIterWeil(p theta4, pre weilPrecomp, n int) theta4 {
	for i := 0; i < n; i++ {
		p = f.thetaDblWeil(p, pre)
	}
	return p
}

// isogeny_chain_weil's balanced split strategy, retaining its normal/dual
// transition after the first step.
func (f *parameters) isogenyChainWeil(invDual weilPoint, pre weilPrecomp, t3, t4 theta4) weilPoint {
	length := f.chainLength - 3
	depth := bits.Len(uint(length-1)) + 1
	ker := make([][2]theta4, depth)
	orders := make([]int, depth)
	ker[0], orders[0] = [2]theta4{t3, t4}, length
	current, step := 0, 0
	for current >= 0 {
		firstDouble := true
		for orders[current] != 1 {
			if firstDouble && step != 0 {
				pre = f.thetaPrecomputeWeil(invDual)
			}
			firstDouble = false
			current++
			n := orders[current-1] / 2
			ker[current] = [2]theta4{
				f.thetaDblIterWeil(ker[current-1][0], pre, n),
				f.thetaDblIterWeil(ker[current-1][1], pre, n),
			}
			orders[current] = orders[current-1] - n
		}
		invDual = f.thetaIsogenyWeilCompute(ker[current], step != 0)
		for j := 0; j < current; j++ {
			ker[j][0] = f.thetaIsogenyWeilEval(ker[j][0], invDual, step != 0)
			ker[j][1] = f.thetaIsogenyWeilEval(ker[j][1], invDual, step != 0)
			orders[j]--
		}
		current--
		step++
	}
	return invDual
}
