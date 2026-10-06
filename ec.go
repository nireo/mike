// SPDX-License-Identifier: Apache-2.0

package mike

import "math/bits"

// ecPoint is a projective Montgomery x-coordinate (X:Z).
type ecPoint struct{ x, z fp2 }

func (f *parameters) ecSwap(p, q ecPoint, choice int) (ecPoint, ecPoint) {
	return ecPoint{f.fp2Select(p.x, q.x, choice), f.fp2Select(p.z, q.z, choice)},
		ecPoint{f.fp2Select(q.x, p.x, choice), f.fp2Select(q.z, p.z, choice)}
}

// ecDblAdd maps to ec_xDBLADD in ec/ref/lvlx/ec.c.
// Returns 2P and P+Q given P, Q, and P-Q.
func (f *parameters) ecDblAdd(p, q, pq ecPoint, a24 fp2) (ecPoint, ecPoint) {
	t0 := f.fp2Add(p.x, p.z)
	t1 := f.fp2Sub(p.x, p.z)
	rx := f.fp2Sqr(t0)
	t2 := f.fp2Sub(q.x, q.z)
	sx := f.fp2Add(q.x, q.z)
	t0 = f.fp2Mul(t0, t2)
	rz := f.fp2Sqr(t1)
	t1 = f.fp2Mul(t1, sx)
	t2 = f.fp2Sub(rx, rz)
	rx = f.fp2Mul(rx, rz)
	sx = f.fp2Mul(a24, t2)
	sz := f.fp2Sub(t0, t1)
	rz = f.fp2Add(rz, sx)
	sx = f.fp2Add(t0, t1)
	rz = f.fp2Mul(rz, t2)
	sz = f.fp2Mul(f.fp2Sqr(sz), pq.x)
	sx = f.fp2Mul(f.fp2Sqr(sx), pq.z)
	return ecPoint{rx, rz}, ecPoint{sx, sz}
}

// ecLadder3pt computes P+[k]Q. Like the C ladder, it processes one extra zero
// bit beyond the scalar bit length, and swaps when the scalar bit is zero.
func (f *parameters) ecLadder3pt(p, q, pq ecPoint, k []byte, a24 fp2) ecPoint {
	x0, x1, x2 := q, p, pq
	for i := 0; i < f.secretBits+1; i++ {
		bit := int(k[i/8] >> (i % 8) & 1)
		x1, x2 = f.ecSwap(x1, x2, 1-bit)
		x0, x1 = f.ecDblAdd(x0, x1, x2, a24)
		x1, x2 = f.ecSwap(x1, x2, 1-bit)
	}
	return x1
}

// ecDblA24 maps to ec_xDBL_A24 in ec/ref/lvlx/isog_chains.c.
// Here a24 is the projective curve constant (A+2C:4C).
func (f *parameters) ecDblA24(p, a24 ecPoint) ecPoint {
	t0 := f.fp2Sqr(f.fp2Add(p.x, p.z))
	t1 := f.fp2Sqr(f.fp2Sub(p.x, p.z))
	t2 := f.fp2Sub(t0, t1)
	t1 = f.fp2Mul(t1, a24.z)
	x := f.fp2Mul(t0, t1)
	t0 = f.fp2Add(f.fp2Mul(t2, a24.x), t1)
	return ecPoint{x, f.fp2Mul(t0, t2)}
}

// ecIsog4 maps to ec_iso_xisog_4. Returns the image curve and evaluation constants.
func (f *parameters) ecIsog4(p ecPoint) (ecPoint, [3]fp2) {
	t1, t2 := f.fp2Sqr(p.x), f.fp2Sqr(p.z)
	t3, t4 := f.fp2Add(t2, t1), f.fp2Sub(t2, t1)
	b := ecPoint{f.fp2Mul(t3, t4), f.fp2Sqr(t2)}
	k2, k1 := f.fp2Add(p.x, p.z), f.fp2Sub(p.x, p.z)
	t2 = f.fp2Add(t2, t2)
	return b, [3]fp2{f.fp2Add(t2, t2), k1, k2}
}

// ecEval4 maps to ec_iso_xeval_4, evaluating a point under a degree-4 isogeny.
func (f *parameters) ecEval4(q ecPoint, k [3]fp2) ecPoint {
	t0, t1 := f.fp2Add(q.x, q.z), f.fp2Sub(q.x, q.z)
	x, z := f.fp2Mul(t0, k[1]), f.fp2Mul(t1, k[2])
	t0 = f.fp2Mul(f.fp2Mul(t0, t1), k[0])
	t1 = f.fp2Sqr(f.fp2Add(x, z))
	z = f.fp2Sqr(f.fp2Sub(x, z))
	x = f.fp2Add(t0, t1)
	t0 = f.fp2Sub(t0, z)
	return ecPoint{f.fp2Mul(x, t1), f.fp2Mul(z, t0)}
}

// ecIsogeny2Chain maps to ec_iso_isogeny_2chain_with_strategy with normalize=2.
// The split stack preserves the C strategy. The last degree-4 step is implicit
// in ecNormalizeMontgomery, exactly as in the reference implementation.
func (f *parameters) ecIsogeny2Chain(kernel ecPoint, a24 fp2, length int) (fp2, bool) {
	// The balanced strategy uses ceil(log2(length))+1 stack slots.
	depth := bits.Len(uint(length-1)) + 1
	splits := make([]ecPoint, depth)
	todo := make([]int, depth)
	splits[0], todo[0] = kernel, length
	a := ecPoint{a24, f.fp2Small(1)}
	current := 0
	for j := 0; j < length/2-1; j++ {
		for todo[current] != 2 {
			current++
			splits[current] = splits[current-1]
			numDbls := todo[current-1]/4*2 + todo[current-1]%2
			todo[current] = todo[current-1] - numDbls
			for i := 0; i < numDbls; i++ {
				splits[current] = f.ecDblA24(splits[current], a)
			}
		}
		var k [3]fp2
		a, k = f.ecIsog4(splits[current])
		for i := 0; i < current; i++ {
			splits[i] = f.ecEval4(splits[i], k)
			todo[i] -= 2
		}
		current--
	}
	return f.ecNormalizeMontgomery(splits[0])
}
