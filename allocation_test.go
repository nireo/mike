package mike

import (
	"runtime"
	"testing"
)

func TestParameterScratchBounds(t *testing.T) {
	for _, f := range allParameters {
		if f.limbCount > maxFieldLimbs || f.fieldBytes > maxPublicKeySize/2 {
			t.Fatalf("%s exceeds field storage", f.name)
		}
		if f.chainLength+f.hdMargin > 1<<(maxIsogenyDepth-1) {
			t.Fatalf("%s exceeds isogeny strategy storage", f.name)
		}
	}
}

// Heap allocation in the field hot path was the original performance problem.
// Keep this invariant explicit so a storage/API change cannot quietly undo it.
func TestFieldOperationsDoNotAllocate(t *testing.T) {
	for _, set := range parameterSets {
		t.Run(set.String(), func(t *testing.T) {
			f := allParameters[set]
			x, y := f.fpSmall(17), f.fpNeg(f.fpSmall(1))
			allocations := testing.AllocsPerRun(100, func() {
				sum, difference := f.fpAdd(x, y), f.fpSub(x, y)
				product := f.fpMul(sum, difference)
				inverse := f.fpInv(product)
				selected := f.fpSelect(product, inverse, 1)
				var encoded [maxPublicKeySize / 2]byte
				f.fpEncode(encoded[:f.fieldBytes], selected)
				decoded, err := f.fpDecode(encoded[:f.fieldBytes])
				if err != nil || decoded.Equal(selected) != 1 {
					t.Fatal("field roundtrip failed")
				}
				runtime.KeepAlive(decoded)
			})
			if allocations != 0 {
				t.Fatalf("field hot path allocated %g times", allocations)
			}
		})
	}
}

func TestExchangeDoesNotAllocate(t *testing.T) {
	for _, set := range parameterSets {
		t.Run(set.String(), func(t *testing.T) {
			v := readParameterVectors(t, set)
			peer := decodeHex(t, v.Keypairs[1].PublicKey)
			secret := decodeHex(t, v.Keypairs[0].SecretKey)
			allocations := testing.AllocsPerRun(1, func() {
				shared, err := set.Exchange(peer, secret)
				if err != nil {
					t.Fatal(err)
				}
				runtime.KeepAlive(shared)
			})
			if allocations != 0 {
				t.Fatalf("exchange allocated %g times", allocations)
			}
		})
	}
}
