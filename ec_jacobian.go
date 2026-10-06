// SPDX-License-Identifier: Apache-2.0

package mike

// These formulas map to ec/ref/lvlx/ec.c. Jacobian Montgomery coordinates
// represent (x,y)=(X/Z^2,Y/Z^3) on y^2=x^3+A*x^2+x.
type ecJacPoint struct{ x, y, z fp2 }
type ecBary struct{ u, v, w fp2 }

func ecJacSelect(p, q ecJacPoint, choice int) ecJacPoint {
	return ecJacPoint{fp2Select(p.x, q.x, choice), fp2Select(p.y, q.y, choice), fp2Select(p.z, q.z, choice)}
}
func ecJacNeg(p ecJacPoint) ecJacPoint { return ecJacPoint{p.x, fp2Neg(p.y), p.z} }
func ecJacToXZ(p ecJacPoint) ecPoint {
	return ecPoint{fp2Select(p.x, fp2Small(1), fp2ZeroChoice(p.z)), fp2Sqr(p.z)}
}

func ecXZToJac(p ecPoint, a fp2) (ecJacPoint, bool) {
	if fp2IsZero(p.z) {
		return ecJacPoint{}, false
	}
	x := fp2Mul(p.x, fp2Inv(p.z))
	y2 := fp2Mul(fp2Add(fp2Mul(fp2Add(x, a), x), fp2Small(1)), x)
	y, ok := fp2Sqrt(y2)
	return ecJacPoint{x, y, fp2Small(1)}, ok
}

func ecJacAdd(p, q ecJacPoint, a fp2) ecJacPoint {
	ctl1, ctl2 := fp2ZeroChoice(p.z), fp2ZeroChoice(q.z)
	t0, t1 := fp2Sqr(p.z), fp2Sqr(q.z)
	v1 := fp2Mul(fp2Mul(t1, q.z), p.y)
	t2 := fp2Mul(fp2Mul(t0, p.z), q.y)
	dy := fp2Sub(t2, v1)
	u2, u1 := fp2Mul(t0, q.x), fp2Mul(t1, p.x)
	dx := fp2Sub(u2, u1)
	t1 = fp2Add(p.y, p.y)
	t2 = fp2Add(a, a)
	t2 = fp2Mul(fp2Add(fp2Mul(t2, p.x), t0), t0)
	t0 = fp2Sqr(p.x)
	t2 = fp2Add(fp2Add(fp2Add(t2, t0), t0), t0)
	t2 = fp2Mul(t2, q.z)
	ctl := fp2ZeroChoice(dx) & fp2ZeroChoice(dy)
	dx, dy = fp2Select(dx, t1, ctl), fp2Select(dy, t2, ctl)
	t0 = fp2Mul(p.z, q.z)
	t1, t2 = fp2Sqr(t0), fp2Sqr(dx)
	t3 := fp2Sqr(dy)
	x := fp2Sub(t3, fp2Mul(fp2Add(fp2Add(fp2Mul(a, t1), u1), u2), t2))
	y := fp2Mul(fp2Sub(fp2Mul(u1, t2), x), dy)
	t3 = fp2Mul(fp2Mul(t2, dx), v1)
	y = fp2Sub(y, t3)
	z := fp2Mul(dx, t0)
	r := ecJacSelect(ecJacPoint{x, y, z}, q, ctl1)
	return ecJacSelect(r, p, ctl2)
}

func ecJacDbl(p ecJacPoint, a fp2) ecJacPoint {
	t0 := fp2Sqr(p.x)
	t1 := fp2Add(t0, t0)
	t0 = fp2Add(t0, t1)
	t1 = fp2Sqr(p.z)
	t2 := fp2Mul(p.x, a)
	t2 = fp2Add(t2, t2)
	t2 = fp2Add(t0, fp2Mul(t1, fp2Add(t1, t2)))
	z := fp2Mul(p.y, p.z)
	z = fp2Add(z, z)
	t0 = fp2Mul(fp2Sqr(z), a)
	t1 = fp2Sqr(p.y)
	t1 = fp2Add(t1, t1)
	t3 := fp2Mul(t1, fp2Add(p.x, p.x))
	x := fp2Sub(fp2Sub(fp2Sub(fp2Sqr(t2), t0), t3), t3)
	y := fp2Mul(fp2Sub(t3, x), t2)
	t1 = fp2Sqr(t1)
	y = fp2Sub(fp2Sub(y, t1), t1)
	return ecJacPoint{x, y, z}
}

// Repeated doubling uses the C modified Weierstrass formulas for n>2.
func ecJacDblIter(p ecJacPoint, n int, a fp2) ecJacPoint {
	if n <= 2 {
		for i := 0; i < n; i++ {
			p = ecJacDbl(p, a)
		}
		return p
	}
	aOver3 := fp2Mul(a, fp2Inv(fp2Small(3)))
	wa := fp2Sub(fp2Small(1), fp2Mul(aOver3, a))
	z2 := fp2Sqr(p.z)
	x, y, z, t := fp2Add(p.x, fp2Mul(aOver3, z2)), p.y, p.z, fp2Mul(wa, fp2Sqr(z2))
	for i := 0; i < n; i++ {
		xx := fp2Sqr(x)
		c := fp2Sqr(y)
		c = fp2Add(c, c)
		cc := fp2Sqr(c)
		r := fp2Add(cc, cc)
		s := fp2Sub(fp2Sub(fp2Sqr(fp2Add(x, c)), xx), cc)
		m := fp2Add(fp2Add(fp2Add(xx, xx), xx), t)
		xNew := fp2Sub(fp2Sub(fp2Sqr(m), s), s)
		zNew := fp2Mul(y, z)
		zNew = fp2Add(zNew, zNew)
		yNew := fp2Sub(fp2Mul(fp2Sub(s, xNew), m), r)
		t = fp2Mul(t, r)
		t = fp2Add(t, t)
		x, y, z = xNew, yNew, zNew
	}
	return ecJacPoint{fp2Sub(x, fp2Mul(aOver3, fp2Sqr(z))), y, z}
}

// ecMulShifted preserves the reference ladder's implicit leading 1. kbits
// excludes that bit; shifting changes both the explicit and implicit bits.
func ecMulShifted(p ecPoint, k []byte, kbits, shift int, a24 fp2) (ecPoint, ecPoint) {
	r0, r1 := p, ecDblA24(p, ecPoint{a24, fp2Small(1)})
	prev := 0
	for i := kbits - 1; i >= shift; i-- {
		bit := 0
		if i/8 < len(k) {
			bit = int(k[i/8] >> (i % 8) & 1)
		}
		r0, r1 = ecSwap(r0, r1, bit^prev)
		prev = bit
		r0, r1 = ecDblAdd(r0, r1, p, a24)
	}
	return ecSwap(r0, r1, prev)
}

func ecRecoverY(p ecJacPoint, q, pq ecPoint, a fp2) ecJacPoint {
	z2 := fp2Sqr(p.z)
	pz, px, py := fp2Mul(z2, p.z), fp2Mul(p.x, p.z), p.y
	v1, v5 := fp2Mul(px, q.z), fp2Mul(q.x, pz)
	v2, v3 := fp2Add(v5, v1), fp2Sub(v5, v1)
	v3 = fp2Mul(fp2Sqr(v3), pq.x)
	v6 := fp2Mul(pz, q.z)
	v1 = fp2Mul(a, v6)
	v1 = fp2Add(v1, v1)
	v2 = fp2Add(v1, v2)
	v4 := fp2Add(fp2Mul(px, q.x), v6)
	v2 = fp2Mul(v2, v4)
	v1 = fp2Mul(v1, v6)
	v2 = fp2Mul(fp2Sub(v2, v1), pq.z)
	ry := fp2Sub(v2, v3)
	v1 = fp2Mul(fp2Mul(fp2Add(py, py), v6), pq.z)
	rx, rz := fp2Mul(v1, q.x), fp2Mul(v1, q.z)
	ry = fp2Select(ry, fp2Small(1), fp2ZeroChoice(pz)|fp2ZeroChoice(q.z))
	ctl := fp2ZeroChoice(pq.z)
	rx, ry, rz = fp2Select(rx, px, ctl), fp2Select(ry, fp2Neg(py), ctl), fp2Select(rz, pz, ctl)
	z2 = fp2Sqr(rz)
	x, y := fp2Mul(rx, rz), fp2Mul(ry, z2)
	y = fp2Select(y, fp2Small(1), fp2ZeroChoice(rz))
	return ecJacPoint{x, y, rz}
}

func ecJacMul(p ecJacPoint, k []byte, kbits, shift int, a, a24 fp2) ecJacPoint {
	q, r := ecMulShifted(ecJacToXZ(p), k, kbits, shift, a24)
	return ecRecoverY(p, q, r, a)
}

func ecJacToBary(p, q ecJacPoint, a fp2) ecBary {
	ctl1, ctl2 := fp2ZeroChoice(p.z), fp2ZeroChoice(q.z)
	zp2, zq2 := fp2Sqr(p.z), fp2Sqr(q.z)
	t2, t3 := fp2Mul(p.x, zq2), fp2Mul(zp2, q.x)
	t4 := fp2Mul(fp2Mul(p.y, q.z), zq2)
	t5 := fp2Mul(fp2Mul(p.z, q.y), zp2)
	t0 := fp2Mul(zp2, zq2)
	t6 := fp2Mul(t4, t5)
	v := fp2Add(t6, t6)
	t4 = fp2Add(fp2Sqr(t4), fp2Sqr(t5))
	t5 = fp2Add(t2, t3)
	t6 = fp2Sqr(fp2Sub(t5, fp2Add(t3, t3)))
	t1 := fp2Mul(fp2Add(t5, fp2Mul(a, t0)), t6)
	u, w := fp2Sub(t4, t1), fp2Mul(t6, t0)
	u = fp2Select(u, q.x, ctl1)
	v = fp2Select(v, fp2Small(0), ctl1|ctl2)
	w = fp2Select(w, zq2, ctl1)
	u = fp2Select(u, p.x, ctl2)
	w = fp2Select(w, zp2, ctl2)
	return ecBary{u, v, w}
}
