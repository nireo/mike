// SPDX-License-Identifier: Apache-2.0

package bigmod

// NewNatWithStorage returns a Nat backed by caller-owned limbs. Its announced
// length is len(limbs); the caller must supply reduced values when an operation
// requires them. The storage must remain valid for the lifetime of the Nat and
// must not be shared with another mutable Nat.
//
// This storage adapter leaves the upstream arithmetic unchanged and lets
// callers use fixed-size stack arrays instead of allocating each result.
func NewNatWithStorage(limbs []uint) Nat {
	return Nat{limbs: limbs}
}

// ToMontgomery converts a reduced value into Montgomery representation.
// The modulus must be odd and x must have its limb count.
func (x *Nat) ToMontgomery(m *Modulus) *Nat { return x.montgomeryRepresentation(m) }

// FromMontgomery converts a reduced value out of Montgomery representation.
// The modulus must be odd and x must have its limb count.
func (x *Nat) FromMontgomery(m *Modulus) *Nat { return x.montgomeryReduction(m) }

// MulMontgomery multiplies reduced Montgomery values, retaining that
// representation. The modulus must be odd. Like Mul, both operands must have
// the modulus's limb count.
func (x *Nat) MulMontgomery(y *Nat, m *Modulus) *Nat {
	return x.montgomeryMul(x, y, m)
}
