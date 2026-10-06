// SPDX-License-Identifier: Apache-2.0

package mike

// These routines map to weil/ref/lvlx/gluing.c. The three stages are Scholten
// gluing, the diagonal dimension-2 isogeny, and Weil gluing in dimension 4.
type scholtenPrecomp struct{ a, b, c, d, e fp }
type scholtenGluing struct {
	pre    scholtenPrecomp
	invAux theta2
	aux    ecJacPoint
	curve  fp2
}
type diagGluing struct {
	u, v       theta2Struct
	uPre, vPre theta2Precomp
}
type weilGluing struct {
	invDual weilPoint
	pre     weilPrecomp
	invAux  theta4
}
type mikeGluing struct {
	scholten   scholtenGluing
	diag       diagGluing
	weil       weilGluing
	aux1, aux2 ecJacPoint
}

func (f *parameters) scholtenVariableCompute(p ecPoint) theta2 {
	xn, zn := f.fp2Norm(p.x), f.fp2Norm(p.z)
	t1 := f.fpAdd(f.fpMul(p.x.re, p.z.re), f.fpMul(p.x.im, p.z.im))
	t3 := f.fpSub(f.fpMul(p.x.im, p.z.re), f.fpMul(p.x.re, p.z.im))
	return theta2{f.fpAdd(xn, zn), f.fpAdd(t1, t1), f.fpSub(zn, xn), f.fpAdd(t3, t3)}
}

func (f *parameters) scholtenJacobianToTheta(m theta2, p ecPoint) theta2 {
	nx, nz := f.fp2Norm(p.x), f.fp2Norm(p.z)
	nadd, nsub := f.fpAdd(nx, nz), f.fpSub(nx, nz)
	txz := f.fpAdd(f.fpMul(p.x.re, p.z.re), f.fpMul(p.x.im, p.z.im))
	txz = f.fpAdd(txz, txz)
	tixz := f.fpSub(f.fpMul(p.x.im, p.z.re), f.fpMul(p.x.re, p.z.im))
	tixz = f.fpAdd(tixz, tixz)
	return theta2{
		f.fpSub(f.fpMul(m[0], nadd), f.fpMul(m[1], txz)),
		f.fpSub(f.fpMul(m[0], txz), f.fpMul(m[1], nadd)),
		f.fpSub(f.fpMul(m[2], nsub), f.fpMul(m[3], tixz)),
		f.fpAdd(f.fpMul(m[2], tixz), f.fpMul(m[3], nsub)),
	}
}

func (f *parameters) scholtenPrecompute(m theta2) scholtenPrecomp {
	d, e := f.fpMul(m[0], m[1]), f.fpMul(m[2], m[3])
	d = f.fpAdd(d, d)
	d = f.fpAdd(d, d)
	e = f.fpAdd(e, e)
	e = f.fpAdd(e, e)
	m0, m1, m2 := f.fpSqr(m[0]), f.fpSqr(m[1]), f.fpSqr(m[2])
	return scholtenPrecomp{f.fpAdd(m1, m2), f.fpSub(m0, m1), f.fpSub(m0, m2), d, e}
}

func (f *parameters) scholtenEval(uvw ecBary, pre scholtenPrecomp) theta2 {
	u2, v2, w2 := f.fp2Sqr(uvw.u), f.fp2Sqr(uvw.v), f.fp2Sqr(uvw.w)
	un, vn, wn := f.fp2Norm(uvw.u), f.fp2Norm(uvw.v), f.fp2Norm(uvw.w)
	un, vn, wn = f.fpAdd(un, un), f.fpAdd(vn, vn), f.fpAdd(wn, wn)
	uw := f.fp2Mul(uvw.u, uvw.w)
	unwn, vnwn := f.fpMul(un, wn), f.fpMul(vn, wn)
	tmp := f.fp2Sub(u2, v2)
	plus, minus := f.fp2Add(tmp, w2), f.fp2Sub(tmp, w2)
	pn, mn := f.fp2Norm(plus), f.fp2Norm(minus)
	uv := f.fp2Mul(plus, f.fp2Frob(uw))
	a, b := f.fpMul(uv.re, pre.d), f.fpMul(uv.im, pre.e)
	out0 := f.fpAdd(f.fpMul(pre.a, pn), f.fpMul(pre.c, unwn))
	out0 = f.fpSub(f.fpSub(out0, a), b)
	out2 := f.fpAdd(f.fpMul(pre.c, pn), f.fpMul(pre.a, unwn))
	out2 = f.fpAdd(f.fpSub(out2, a), b)
	// MIKE always evaluates on the twist, so the last coordinate is negated.
	return theta2{out0, f.fpMul(pre.b, mn), out2, f.fpNeg(f.fpMul(pre.b, vnwn))}
}

func (f *parameters) scholtenComputeAndVerify(p8, q8 ecJacPoint, a fp2) (scholtenGluing, bool) {
	phi := scholtenGluing{aux: p8, curve: a}
	p4 := f.ecJacDbl(p8, a)
	xzp4 := f.ecJacToXZ(p4)
	p2 := f.ecJacDbl(p4, a)
	q4 := f.ecJacDbl(q8, a)
	qz2 := f.fp2Sqr(q4.z)
	normalized, ok := f.ecNormalizeMontgomery(xzp4)
	if !ok || a.im.IsZero() == 1 || !f.fp2IsZero(p2.y) || f.fp2IsZero(p2.z) ||
		f.fp2IsZero(q4.z) ||
		(f.fp2EqualChoice(q4.x, qz2)|f.fp2EqualChoice(q4.x, f.fp2Neg(qz2))) == 0 ||
		f.fp2EqualChoice(normalized, a) == 0 {
		return scholtenGluing{}, false
	}
	m := f.scholtenVariableCompute(xzp4)
	phi.pre = f.scholtenPrecompute(m)
	h1 := f.thetaSqr2(f.scholtenJacobianToTheta(m, f.ecJacToXZ(p8)))
	h2 := f.thetaSqr2(f.scholtenJacobianToTheta(m, f.ecJacToXZ(q8)))
	h1[3], h2[3] = f.fpNeg(h1[3]), f.fpNeg(h2[3])
	h1, h2 = f.thetaH2(h1), f.thetaH2(h2)
	t0, t2 := f.fpMul(h1[2], h2[0]), f.fpMul(h1[0], h2[2])
	phi.invAux = theta2{t0, t0, t2, t2}
	return phi, true
}

func (f *parameters) scholtenGluingEval(p ecJacPoint, phi scholtenGluing) theta2 {
	uvw := f.ecJacToBary(p, phi.aux, phi.curve)
	// Match the reference's infinity case using conditional selection even
	// when evaluating points derived from the secret scalar.
	choice := f.fp2ZeroChoice(uvw.w)
	uvw.u = f.fp2Select(uvw.u, f.fp2Small(1), choice)
	uvw.v = f.fp2Select(uvw.v, f.fp2Small(0), choice)
	return f.thetaDot2(f.scholtenEval(uvw, phi.pre), phi.invAux)
}

func (f *parameters) gluingChangeU(x theta2) theta2 {
	a, b := f.fpAdd(x[0], x[1]), f.fpSub(x[0], x[1])
	c, d := f.fpAdd(x[2], x[3]), f.fpSub(x[2], x[3])
	return theta2{f.fpAdd(a, c), f.fpAdd(b, d), f.fpSub(a, c), f.fpSub(d, b)}
}
func (f *parameters) gluingChangeV(x theta2) theta2 {
	a, b := f.fpAdd(x[0], x[1]), f.fpSub(x[0], x[1])
	c, d := f.fpAdd(x[2], x[3]), f.fpSub(x[2], x[3])
	return theta2{f.fpAdd(a, d), f.fpSub(a, d), f.fpAdd(c, b), f.fpSub(c, b)}
}

func (f *parameters) gluingDiagCompute(v1, v2 theta2) diagGluing {
	u0, u1 := v2, v1
	u0[3], u1[3] = f.fpNeg(u0[3]), f.fpNeg(u1[3])
	u := f.thetaIsogeny2Compute([2]theta2{f.gluingChangeU(u0), f.gluingChangeU(u1)})
	v := f.thetaIsogeny2Compute([2]theta2{f.gluingChangeV(v1), f.gluingChangeV(v2)})
	return diagGluing{u, v, f.thetaPrecompute2(u), f.thetaPrecompute2(v)}
}
func (f *parameters) gluingDiagEval(x, y theta2, phi diagGluing) (theta2, theta2) {
	return f.thetaIsogeny2Eval(f.gluingChangeU(x), phi.u), f.thetaIsogeny2Eval(f.gluingChangeV(y), phi.v)
}

var gluingChangeStruct4 = [16]int{0, 5, 10, 15, 1, 4, 11, 14, 8, 13, 2, 7, 9, 12, 3, 6}

func (f *parameters) gluingCoupleTo4(x, y theta2) theta4 {
	y = f.thetaH2(y)
	var tensor, out theta4
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			tensor[4*i+j] = f.fpMul(x[i], y[j])
		}
	}
	for i := 0; i < 4; i++ {
		var block theta2
		for j := 0; j < 4; j++ {
			block[j] = tensor[gluingChangeStruct4[4*i+j]]
		}
		block = f.thetaH2(block)
		copy(out[4*i:4*i+4], block[:])
	}
	return out
}

func (f *parameters) gluingSpecialInv(x weilPoint) weilPoint {
	indices := [7]int{0, 1, 2, 3, 5, 7, 9}
	var nonzero [7]fp
	for i, j := range indices {
		nonzero[i] = x[j]
	}
	inverse := f.fpProjectiveInverse(nonzero[:])
	var out weilPoint
	for i := range out {
		out[i] = f.fpSmall(0)
	}
	for i, j := range indices {
		out[j] = inverse[i]
	}
	return out
}

func (f *parameters) solveGluingHIIP(h [4]theta4) (weilPoint, theta4) {
	leg4 := [3]fp{f.fpMul(h[0][4], h[0][6]), f.fpMul(h[0][0], h[0][6]), f.fpMul(h[0][0], h[0][2])}
	leg8 := [3]fp{f.fpMul(h[1][8], h[1][9]), f.fpMul(h[1][0], h[1][9]), f.fpMul(h[1][0], h[1][1])}
	leg12 := [3]fp{f.fpMul(h[2][12], h[2][15]), f.fpMul(h[2][0], h[2][15]), f.fpMul(h[2][0], h[2][3])}
	var invDual weilPoint
	tmp := f.fpMul(leg8[0], leg12[0])
	invDual[0], invDual[2], invDual[5] = f.fpMul(tmp, leg4[0]), f.fpMul(tmp, leg4[1]), f.fpMul(tmp, leg4[2])
	tmp = f.fpMul(leg4[0], leg12[0])
	invDual[1], invDual[7] = f.fpMul(tmp, leg8[1]), f.fpMul(tmp, leg8[2])
	tmp = f.fpMul(leg4[0], leg8[0])
	invDual[3], invDual[9] = f.fpMul(tmp, leg12[1]), f.fpMul(tmp, leg12[2])
	invDual[4], invDual[6], invDual[8] = f.fpSmall(0), f.fpSmall(0), f.fpSmall(0)
	aux := [8]fp{
		f.fpMul(h[0][0], invDual[0]), f.fpMul(h[0][1], invDual[1]),
		f.fpMul(h[0][2], invDual[2]), f.fpMul(h[0][3], invDual[3]),
		f.fpMul(h[0][8], invDual[1]), f.fpMul(h[0][9], invDual[7]),
		f.fpSmall(0), f.fpMul(h[0][15], invDual[9]),
	}
	aux[6] = f.fpMul(aux[0], f.fpMul(h[3][2], invDual[2]))
	tmp = f.fpMul(h[3][8], invDual[1])
	for i := range aux {
		if i != 6 {
			aux[i] = f.fpMul(aux[i], tmp)
		}
	}
	inverse := f.fpProjectiveInverse(aux[:])
	var invAux theta4
	for i := 0; i < 2; i++ {
		for j := 0; j < 4; j++ {
			invAux[8*i+j], invAux[8*i+j+4] = inverse[4*i+j], inverse[4*i+j]
		}
	}
	return invDual, invAux
}

func (f *parameters) gluingComputeWeil(t3, t4, t34, t3p2t4 theta4) weilGluing {
	h := [4]theta4{t3, t4, t34, t3p2t4}
	for i := range h {
		h[i] = f.thetaH4(f.thetaSqr4(h[i]))
	}
	invDual, invAux := f.solveGluingHIIP(h)
	null := f.thetaHWeil(f.gluingSpecialInv(invDual))
	pre := weilPrecomp{f.thetaInvWeil(null), f.thetaInvWeil(f.thetaHWeil(f.thetaSqrWeil(null)))}
	return weilGluing{invDual, pre, invAux}
}

func (f *parameters) gluingMikeCompute(a fp2, basis gluingBasis) (mikeGluing, bool) {
	scholten, ok := f.scholtenComputeAndVerify(basis.p8, basis.q8, a)
	if !ok {
		return mikeGluing{}, false
	}
	g := mikeGluing{scholten: scholten, aux1: basis.t31, aux2: basis.t32}
	t341, t342 := f.ecJacAdd(basis.t31, basis.t41, a), f.ecJacAdd(basis.t32, basis.t42, a)
	v1, v2 := f.scholtenGluingEval(basis.q16, scholten), f.scholtenGluingEval(basis.p16, scholten)
	g.diag = f.gluingDiagCompute(v1, v2)
	t31, t32 := f.gluingDiagEval(f.scholtenGluingEval(basis.t31, scholten), f.scholtenGluingEval(basis.t32, scholten), g.diag)
	t41, t42 := f.gluingDiagEval(f.scholtenGluingEval(basis.t41, scholten), f.scholtenGluingEval(basis.t42, scholten), g.diag)
	t341th, t342th := f.gluingDiagEval(f.scholtenGluingEval(t341, scholten), f.scholtenGluingEval(t342, scholten), g.diag)
	t3p2t41 := f.thetaDiffAdd2(t341th, t41, f.thetaInv2(t31), g.diag.uPre)
	t3p2t42 := f.thetaDiffAdd2(t342th, t42, f.thetaInv2(t32), g.diag.vPre)
	g.weil = f.gluingComputeWeil(f.gluingCoupleTo4(t31, t32), f.gluingCoupleTo4(t41, t42),
		f.gluingCoupleTo4(t341th, t342th), f.gluingCoupleTo4(t3p2t41, t3p2t42))
	return g, true
}

func (f *parameters) gluingMikeEval(t1, t2 ecJacPoint, g mikeGluing) theta4 {
	a := g.scholten.curve
	t1plus, t1minus := f.ecJacAdd(t1, g.aux1, a), f.ecJacAdd(t1, f.ecJacNeg(g.aux1), a)
	t2plus, t2minus := f.ecJacAdd(t2, g.aux2, a), f.ecJacAdd(t2, f.ecJacNeg(g.aux2), a)
	p1, p2 := f.gluingDiagEval(f.scholtenGluingEval(t1plus, g.scholten), f.scholtenGluingEval(t2plus, g.scholten), g.diag)
	m1, m2 := f.gluingDiagEval(f.scholtenGluingEval(t1minus, g.scholten), f.scholtenGluingEval(t2minus, g.scholten), g.diag)
	plus, minus := f.gluingCoupleTo4(p1, p2), f.gluingCoupleTo4(m1, m2)
	return f.thetaH4(f.thetaDot4(f.thetaH4(f.thetaDot4(plus, minus)), g.weil.invAux))
}
