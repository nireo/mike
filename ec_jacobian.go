// SPDX-License-Identifier: Apache-2.0

package mike

// These formulas map to ec/ref/lvlx/ec.c. Jacobian Montgomery coordinates
// represent (x,y)=(X/Z^2,Y/Z^3) on y^2=x^3+A*x^2+x.
type ecJacPoint struct{ x, y, z fp2 }
type ecBary struct{ u, v, w fp2 }

func (f *parameters) ecJacSelect(p, q ecJacPoint, choice int) ecJacPoint {
	return ecJacPoint{f.fp2Select(p.x, q.x, choice), f.fp2Select(p.y, q.y, choice), f.fp2Select(p.z, q.z, choice)}
}
func (f *parameters) ecJacNeg(p ecJacPoint) ecJacPoint { return ecJacPoint{p.x, f.fp2Neg(p.y), p.z} }
func (f *parameters) ecJacToXZ(p ecJacPoint) ecPoint {
	return ecPoint{f.fp2Select(p.x, f.fp2Small(1), f.fp2ZeroChoice(p.z)), f.fp2Sqr(p.z)}
}

func (f *parameters) ecXZToJac(p ecPoint, a fp2) (ecJacPoint, bool) {
	if f.fp2IsZero(p.z) {
		return ecJacPoint{}, false
	}
	x := f.fp2Mul(p.x, f.fp2Inv(p.z))
	y2 := f.fp2Mul(f.fp2Add(f.fp2Mul(f.fp2Add(x, a), x), f.fp2Small(1)), x)
	y, ok := f.fp2Sqrt(y2)
	return ecJacPoint{x, y, f.fp2Small(1)}, ok
}

func (f *parameters) ecJacAdd(p, q ecJacPoint, a fp2) ecJacPoint {
	ctl1, ctl2 := f.fp2ZeroChoice(p.z), f.fp2ZeroChoice(q.z)
	t0, t1 := f.fp2Sqr(p.z), f.fp2Sqr(q.z)
	v1 := f.fp2Mul(f.fp2Mul(t1, q.z), p.y)
	t2 := f.fp2Mul(f.fp2Mul(t0, p.z), q.y)
	dy := f.fp2Sub(t2, v1)
	u2, u1 := f.fp2Mul(t0, q.x), f.fp2Mul(t1, p.x)
	dx := f.fp2Sub(u2, u1)
	t1 = f.fp2Add(p.y, p.y)
	t2 = f.fp2Add(a, a)
	t2 = f.fp2Mul(f.fp2Add(f.fp2Mul(t2, p.x), t0), t0)
	t0 = f.fp2Sqr(p.x)
	t2 = f.fp2Add(f.fp2Add(f.fp2Add(t2, t0), t0), t0)
	t2 = f.fp2Mul(t2, q.z)
	ctl := f.fp2ZeroChoice(dx) & f.fp2ZeroChoice(dy)
	dx, dy = f.fp2Select(dx, t1, ctl), f.fp2Select(dy, t2, ctl)
	t0 = f.fp2Mul(p.z, q.z)
	t1, t2 = f.fp2Sqr(t0), f.fp2Sqr(dx)
	t3 := f.fp2Sqr(dy)
	x := f.fp2Sub(t3, f.fp2Mul(f.fp2Add(f.fp2Add(f.fp2Mul(a, t1), u1), u2), t2))
	y := f.fp2Mul(f.fp2Sub(f.fp2Mul(u1, t2), x), dy)
	t3 = f.fp2Mul(f.fp2Mul(t2, dx), v1)
	y = f.fp2Sub(y, t3)
	z := f.fp2Mul(dx, t0)
	r := f.ecJacSelect(ecJacPoint{x, y, z}, q, ctl1)
	return f.ecJacSelect(r, p, ctl2)
}

func (f *parameters) ecJacDbl(p ecJacPoint, a fp2) ecJacPoint {
	t0 := f.fp2Sqr(p.x)
	t1 := f.fp2Add(t0, t0)
	t0 = f.fp2Add(t0, t1)
	t1 = f.fp2Sqr(p.z)
	t2 := f.fp2Mul(p.x, a)
	t2 = f.fp2Add(t2, t2)
	t2 = f.fp2Add(t0, f.fp2Mul(t1, f.fp2Add(t1, t2)))
	z := f.fp2Mul(p.y, p.z)
	z = f.fp2Add(z, z)
	t0 = f.fp2Mul(f.fp2Sqr(z), a)
	t1 = f.fp2Sqr(p.y)
	t1 = f.fp2Add(t1, t1)
	t3 := f.fp2Mul(t1, f.fp2Add(p.x, p.x))
	x := f.fp2Sub(f.fp2Sub(f.fp2Sub(f.fp2Sqr(t2), t0), t3), t3)
	y := f.fp2Mul(f.fp2Sub(t3, x), t2)
	t1 = f.fp2Sqr(t1)
	y = f.fp2Sub(f.fp2Sub(y, t1), t1)
	return ecJacPoint{x, y, z}
}

// Repeated doubling uses the C modified Weierstrass formulas for n>2.
func (f *parameters) ecJacDblIter(p ecJacPoint, n int, a fp2) ecJacPoint {
	if n <= 2 {
		for i := 0; i < n; i++ {
			p = f.ecJacDbl(p, a)
		}
		return p
	}
	aOver3 := f.fp2Mul(a, f.fp2Inv(f.fp2Small(3)))
	wa := f.fp2Sub(f.fp2Small(1), f.fp2Mul(aOver3, a))
	z2 := f.fp2Sqr(p.z)
	x, y, z, t := f.fp2Add(p.x, f.fp2Mul(aOver3, z2)), p.y, p.z, f.fp2Mul(wa, f.fp2Sqr(z2))
	for i := 0; i < n; i++ {
		xx := f.fp2Sqr(x)
		c := f.fp2Sqr(y)
		c = f.fp2Add(c, c)
		cc := f.fp2Sqr(c)
		r := f.fp2Add(cc, cc)
		s := f.fp2Sub(f.fp2Sub(f.fp2Sqr(f.fp2Add(x, c)), xx), cc)
		m := f.fp2Add(f.fp2Add(f.fp2Add(xx, xx), xx), t)
		xNew := f.fp2Sub(f.fp2Sub(f.fp2Sqr(m), s), s)
		zNew := f.fp2Mul(y, z)
		zNew = f.fp2Add(zNew, zNew)
		yNew := f.fp2Sub(f.fp2Mul(f.fp2Sub(s, xNew), m), r)
		t = f.fp2Mul(t, r)
		t = f.fp2Add(t, t)
		x, y, z = xNew, yNew, zNew
	}
	return ecJacPoint{f.fp2Sub(x, f.fp2Mul(aOver3, f.fp2Sqr(z))), y, z}
}

// ecMulShifted preserves the reference ladder's implicit leading 1. kbits
// excludes that bit; shifting changes both the explicit and implicit bits.
func (f *parameters) ecMulShifted(p ecPoint, k []byte, kbits, shift int, a24 fp2) (ecPoint, ecPoint) {
	r0, r1 := p, f.ecDblA24(p, ecPoint{a24, f.fp2Small(1)})
	prev := 0
	for i := kbits - 1; i >= shift; i-- {
		bit := 0
		if i/8 < len(k) {
			bit = int(k[i/8] >> (i % 8) & 1)
		}
		r0, r1 = f.ecSwap(r0, r1, bit^prev)
		prev = bit
		r0, r1 = f.ecDblAdd(r0, r1, p, a24)
	}
	return f.ecSwap(r0, r1, prev)
}

func (f *parameters) ecRecoverY(p ecJacPoint, q, pq ecPoint, a fp2) ecJacPoint {
	z2 := f.fp2Sqr(p.z)
	pz, px, py := f.fp2Mul(z2, p.z), f.fp2Mul(p.x, p.z), p.y
	v1, v5 := f.fp2Mul(px, q.z), f.fp2Mul(q.x, pz)
	v2, v3 := f.fp2Add(v5, v1), f.fp2Sub(v5, v1)
	v3 = f.fp2Mul(f.fp2Sqr(v3), pq.x)
	v6 := f.fp2Mul(pz, q.z)
	v1 = f.fp2Mul(a, v6)
	v1 = f.fp2Add(v1, v1)
	v2 = f.fp2Add(v1, v2)
	v4 := f.fp2Add(f.fp2Mul(px, q.x), v6)
	v2 = f.fp2Mul(v2, v4)
	v1 = f.fp2Mul(v1, v6)
	v2 = f.fp2Mul(f.fp2Sub(v2, v1), pq.z)
	ry := f.fp2Sub(v2, v3)
	v1 = f.fp2Mul(f.fp2Mul(f.fp2Add(py, py), v6), pq.z)
	rx, rz := f.fp2Mul(v1, q.x), f.fp2Mul(v1, q.z)
	ry = f.fp2Select(ry, f.fp2Small(1), f.fp2ZeroChoice(pz)|f.fp2ZeroChoice(q.z))
	ctl := f.fp2ZeroChoice(pq.z)
	rx, ry, rz = f.fp2Select(rx, px, ctl), f.fp2Select(ry, f.fp2Neg(py), ctl), f.fp2Select(rz, pz, ctl)
	z2 = f.fp2Sqr(rz)
	x, y := f.fp2Mul(rx, rz), f.fp2Mul(ry, z2)
	y = f.fp2Select(y, f.fp2Small(1), f.fp2ZeroChoice(rz))
	return ecJacPoint{x, y, rz}
}

func (f *parameters) ecJacMul(p ecJacPoint, k []byte, kbits, shift int, a, a24 fp2) ecJacPoint {
	q, r := f.ecMulShifted(f.ecJacToXZ(p), k, kbits, shift, a24)
	return f.ecRecoverY(p, q, r, a)
}

func (f *parameters) ecJacToBary(p, q ecJacPoint, a fp2) ecBary {
	ctl1, ctl2 := f.fp2ZeroChoice(p.z), f.fp2ZeroChoice(q.z)
	zp2, zq2 := f.fp2Sqr(p.z), f.fp2Sqr(q.z)
	t2, t3 := f.fp2Mul(p.x, zq2), f.fp2Mul(zp2, q.x)
	t4 := f.fp2Mul(f.fp2Mul(p.y, q.z), zq2)
	t5 := f.fp2Mul(f.fp2Mul(p.z, q.y), zp2)
	t0 := f.fp2Mul(zp2, zq2)
	t6 := f.fp2Mul(t4, t5)
	v := f.fp2Add(t6, t6)
	t4 = f.fp2Add(f.fp2Sqr(t4), f.fp2Sqr(t5))
	t5 = f.fp2Add(t2, t3)
	t6 = f.fp2Sqr(f.fp2Sub(t5, f.fp2Add(t3, t3)))
	t1 := f.fp2Mul(f.fp2Add(t5, f.fp2Mul(a, t0)), t6)
	u, w := f.fp2Sub(t4, t1), f.fp2Mul(t6, t0)
	u = f.fp2Select(u, q.x, ctl1)
	v = f.fp2Select(v, f.fp2Small(0), ctl1|ctl2)
	w = f.fp2Select(w, zq2, ctl1)
	u = f.fp2Select(u, p.x, ctl2)
	w = f.fp2Select(w, zp2, ctl2)
	return ecBary{u, v, w}
}
