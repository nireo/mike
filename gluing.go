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

func scholtenVariableCompute(p ecPoint) theta2 {
	xn, zn := fp2Norm(p.x), fp2Norm(p.z)
	t1 := fpAdd(fpMul(p.x.re, p.z.re), fpMul(p.x.im, p.z.im))
	t3 := fpSub(fpMul(p.x.im, p.z.re), fpMul(p.x.re, p.z.im))
	return theta2{fpAdd(xn, zn), fpAdd(t1, t1), fpSub(zn, xn), fpAdd(t3, t3)}
}

func scholtenJacobianToTheta(m theta2, p ecPoint) theta2 {
	nx, nz := fp2Norm(p.x), fp2Norm(p.z)
	nadd, nsub := fpAdd(nx, nz), fpSub(nx, nz)
	txz := fpAdd(fpMul(p.x.re, p.z.re), fpMul(p.x.im, p.z.im))
	txz = fpAdd(txz, txz)
	tixz := fpSub(fpMul(p.x.im, p.z.re), fpMul(p.x.re, p.z.im))
	tixz = fpAdd(tixz, tixz)
	return theta2{
		fpSub(fpMul(m[0], nadd), fpMul(m[1], txz)),
		fpSub(fpMul(m[0], txz), fpMul(m[1], nadd)),
		fpSub(fpMul(m[2], nsub), fpMul(m[3], tixz)),
		fpAdd(fpMul(m[2], tixz), fpMul(m[3], nsub)),
	}
}

func scholtenPrecompute(m theta2) scholtenPrecomp {
	d, e := fpMul(m[0], m[1]), fpMul(m[2], m[3])
	d = fpAdd(d, d)
	d = fpAdd(d, d)
	e = fpAdd(e, e)
	e = fpAdd(e, e)
	m0, m1, m2 := fpSqr(m[0]), fpSqr(m[1]), fpSqr(m[2])
	return scholtenPrecomp{fpAdd(m1, m2), fpSub(m0, m1), fpSub(m0, m2), d, e}
}

func scholtenEval(uvw ecBary, pre scholtenPrecomp) theta2 {
	u2, v2, w2 := fp2Sqr(uvw.u), fp2Sqr(uvw.v), fp2Sqr(uvw.w)
	un, vn, wn := fp2Norm(uvw.u), fp2Norm(uvw.v), fp2Norm(uvw.w)
	un, vn, wn = fpAdd(un, un), fpAdd(vn, vn), fpAdd(wn, wn)
	uw := fp2Mul(uvw.u, uvw.w)
	unwn, vnwn := fpMul(un, wn), fpMul(vn, wn)
	tmp := fp2Sub(u2, v2)
	plus, minus := fp2Add(tmp, w2), fp2Sub(tmp, w2)
	pn, mn := fp2Norm(plus), fp2Norm(minus)
	uv := fp2Mul(plus, fp2Frob(uw))
	a, b := fpMul(uv.re, pre.d), fpMul(uv.im, pre.e)
	out0 := fpAdd(fpMul(pre.a, pn), fpMul(pre.c, unwn))
	out0 = fpSub(fpSub(out0, a), b)
	out2 := fpAdd(fpMul(pre.c, pn), fpMul(pre.a, unwn))
	out2 = fpAdd(fpSub(out2, a), b)
	// MIKE always evaluates on the twist, so the last coordinate is negated.
	return theta2{out0, fpMul(pre.b, mn), out2, fpNeg(fpMul(pre.b, vnwn))}
}

func scholtenComputeAndVerify(p8, q8 ecJacPoint, a fp2) (scholtenGluing, bool) {
	phi := scholtenGluing{aux: p8, curve: a}
	p4 := ecJacDbl(p8, a)
	xzp4 := ecJacToXZ(p4)
	p2 := ecJacDbl(p4, a)
	q4 := ecJacDbl(q8, a)
	qz2 := fp2Sqr(q4.z)
	normalized, ok := ecNormalizeMontgomery(xzp4)
	if !ok || a.im.IsZero() == 1 || !fp2IsZero(p2.y) || fp2IsZero(p2.z) ||
		fp2IsZero(q4.z) ||
		(fp2EqualChoice(q4.x, qz2)|fp2EqualChoice(q4.x, fp2Neg(qz2))) == 0 ||
		fp2EqualChoice(normalized, a) == 0 {
		return scholtenGluing{}, false
	}
	m := scholtenVariableCompute(xzp4)
	phi.pre = scholtenPrecompute(m)
	h1 := thetaSqr2(scholtenJacobianToTheta(m, ecJacToXZ(p8)))
	h2 := thetaSqr2(scholtenJacobianToTheta(m, ecJacToXZ(q8)))
	h1[3], h2[3] = fpNeg(h1[3]), fpNeg(h2[3])
	h1, h2 = thetaH2(h1), thetaH2(h2)
	t0, t2 := fpMul(h1[2], h2[0]), fpMul(h1[0], h2[2])
	phi.invAux = theta2{t0, t0, t2, t2}
	return phi, true
}

func scholtenGluingEval(p ecJacPoint, phi scholtenGluing) theta2 {
	uvw := ecJacToBary(p, phi.aux, phi.curve)
	// Match the reference's infinity case using conditional selection even
	// when evaluating points derived from the secret scalar.
	choice := fp2ZeroChoice(uvw.w)
	uvw.u = fp2Select(uvw.u, fp2Small(1), choice)
	uvw.v = fp2Select(uvw.v, fp2Small(0), choice)
	return thetaDot2(scholtenEval(uvw, phi.pre), phi.invAux)
}

func gluingChangeU(x theta2) theta2 {
	a, b := fpAdd(x[0], x[1]), fpSub(x[0], x[1])
	c, d := fpAdd(x[2], x[3]), fpSub(x[2], x[3])
	return theta2{fpAdd(a, c), fpAdd(b, d), fpSub(a, c), fpSub(d, b)}
}
func gluingChangeV(x theta2) theta2 {
	a, b := fpAdd(x[0], x[1]), fpSub(x[0], x[1])
	c, d := fpAdd(x[2], x[3]), fpSub(x[2], x[3])
	return theta2{fpAdd(a, d), fpSub(a, d), fpAdd(c, b), fpSub(c, b)}
}

func gluingDiagCompute(v1, v2 theta2) diagGluing {
	u0, u1 := v2, v1
	u0[3], u1[3] = fpNeg(u0[3]), fpNeg(u1[3])
	u := thetaIsogeny2Compute([2]theta2{gluingChangeU(u0), gluingChangeU(u1)})
	v := thetaIsogeny2Compute([2]theta2{gluingChangeV(v1), gluingChangeV(v2)})
	return diagGluing{u, v, thetaPrecompute2(u), thetaPrecompute2(v)}
}
func gluingDiagEval(x, y theta2, phi diagGluing) (theta2, theta2) {
	return thetaIsogeny2Eval(gluingChangeU(x), phi.u), thetaIsogeny2Eval(gluingChangeV(y), phi.v)
}

var gluingChangeStruct4 = [16]int{0, 5, 10, 15, 1, 4, 11, 14, 8, 13, 2, 7, 9, 12, 3, 6}

func gluingCoupleTo4(x, y theta2) theta4 {
	y = thetaH2(y)
	var tensor, out theta4
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			tensor[4*i+j] = fpMul(x[i], y[j])
		}
	}
	for i := 0; i < 4; i++ {
		var block theta2
		for j := 0; j < 4; j++ {
			block[j] = tensor[gluingChangeStruct4[4*i+j]]
		}
		block = thetaH2(block)
		copy(out[4*i:4*i+4], block[:])
	}
	return out
}

func gluingSpecialInv(x weilPoint) weilPoint {
	indices := [7]int{0, 1, 2, 3, 5, 7, 9}
	var nonzero [7]fp
	for i, j := range indices {
		nonzero[i] = x[j]
	}
	inverse := fpProjectiveInverse(nonzero[:])
	var out weilPoint
	for i := range out {
		out[i] = fpSmall(0)
	}
	for i, j := range indices {
		out[j] = inverse[i]
	}
	return out
}

func solveGluingHIIP(h [4]theta4) (weilPoint, theta4) {
	leg4 := [3]fp{fpMul(h[0][4], h[0][6]), fpMul(h[0][0], h[0][6]), fpMul(h[0][0], h[0][2])}
	leg8 := [3]fp{fpMul(h[1][8], h[1][9]), fpMul(h[1][0], h[1][9]), fpMul(h[1][0], h[1][1])}
	leg12 := [3]fp{fpMul(h[2][12], h[2][15]), fpMul(h[2][0], h[2][15]), fpMul(h[2][0], h[2][3])}
	var invDual weilPoint
	tmp := fpMul(leg8[0], leg12[0])
	invDual[0], invDual[2], invDual[5] = fpMul(tmp, leg4[0]), fpMul(tmp, leg4[1]), fpMul(tmp, leg4[2])
	tmp = fpMul(leg4[0], leg12[0])
	invDual[1], invDual[7] = fpMul(tmp, leg8[1]), fpMul(tmp, leg8[2])
	tmp = fpMul(leg4[0], leg8[0])
	invDual[3], invDual[9] = fpMul(tmp, leg12[1]), fpMul(tmp, leg12[2])
	invDual[4], invDual[6], invDual[8] = fpSmall(0), fpSmall(0), fpSmall(0)
	aux := [8]fp{
		fpMul(h[0][0], invDual[0]), fpMul(h[0][1], invDual[1]),
		fpMul(h[0][2], invDual[2]), fpMul(h[0][3], invDual[3]),
		fpMul(h[0][8], invDual[1]), fpMul(h[0][9], invDual[7]),
		fpSmall(0), fpMul(h[0][15], invDual[9]),
	}
	aux[6] = fpMul(aux[0], fpMul(h[3][2], invDual[2]))
	tmp = fpMul(h[3][8], invDual[1])
	for i := range aux {
		if i != 6 {
			aux[i] = fpMul(aux[i], tmp)
		}
	}
	inverse := fpProjectiveInverse(aux[:])
	var invAux theta4
	for i := 0; i < 2; i++ {
		for j := 0; j < 4; j++ {
			invAux[8*i+j], invAux[8*i+j+4] = inverse[4*i+j], inverse[4*i+j]
		}
	}
	return invDual, invAux
}

func gluingComputeWeil(t3, t4, t34, t3p2t4 theta4) weilGluing {
	h := [4]theta4{t3, t4, t34, t3p2t4}
	for i := range h {
		h[i] = thetaH4(thetaSqr4(h[i]))
	}
	invDual, invAux := solveGluingHIIP(h)
	null := thetaHWeil(gluingSpecialInv(invDual))
	pre := weilPrecomp{thetaInvWeil(null), thetaInvWeil(thetaHWeil(thetaSqrWeil(null)))}
	return weilGluing{invDual, pre, invAux}
}

func gluingMikeCompute(a fp2, basis gluingBasis) (mikeGluing, bool) {
	scholten, ok := scholtenComputeAndVerify(basis.p8, basis.q8, a)
	if !ok {
		return mikeGluing{}, false
	}
	g := mikeGluing{scholten: scholten, aux1: basis.t31, aux2: basis.t32}
	t341, t342 := ecJacAdd(basis.t31, basis.t41, a), ecJacAdd(basis.t32, basis.t42, a)
	v1, v2 := scholtenGluingEval(basis.q16, scholten), scholtenGluingEval(basis.p16, scholten)
	g.diag = gluingDiagCompute(v1, v2)
	t31, t32 := gluingDiagEval(scholtenGluingEval(basis.t31, scholten), scholtenGluingEval(basis.t32, scholten), g.diag)
	t41, t42 := gluingDiagEval(scholtenGluingEval(basis.t41, scholten), scholtenGluingEval(basis.t42, scholten), g.diag)
	t341th, t342th := gluingDiagEval(scholtenGluingEval(t341, scholten), scholtenGluingEval(t342, scholten), g.diag)
	t3p2t41 := thetaDiffAdd2(t341th, t41, thetaInv2(t31), g.diag.uPre)
	t3p2t42 := thetaDiffAdd2(t342th, t42, thetaInv2(t32), g.diag.vPre)
	g.weil = gluingComputeWeil(gluingCoupleTo4(t31, t32), gluingCoupleTo4(t41, t42),
		gluingCoupleTo4(t341th, t342th), gluingCoupleTo4(t3p2t41, t3p2t42))
	return g, true
}

func gluingMikeEval(t1, t2 ecJacPoint, g mikeGluing) theta4 {
	a := g.scholten.curve
	t1plus, t1minus := ecJacAdd(t1, g.aux1, a), ecJacAdd(t1, ecJacNeg(g.aux1), a)
	t2plus, t2minus := ecJacAdd(t2, g.aux2, a), ecJacAdd(t2, ecJacNeg(g.aux2), a)
	p1, p2 := gluingDiagEval(scholtenGluingEval(t1plus, g.scholten), scholtenGluingEval(t2plus, g.scholten), g.diag)
	m1, m2 := gluingDiagEval(scholtenGluingEval(t1minus, g.scholten), scholtenGluingEval(t2minus, g.scholten), g.diag)
	plus, minus := gluingCoupleTo4(p1, p2), gluingCoupleTo4(m1, m2)
	return thetaH4(thetaDot4(thetaH4(thetaDot4(plus, minus)), g.weil.invAux))
}
