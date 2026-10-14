package mike

import (
	"crypto/subtle"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// TestTimingReview is an opt-in timing experiment, not a constant-time test.
// It reports raw Welch t statistics without asserting a noisy pass threshold.
// Run alone, without -race, coverage, or fuzz instrumentation:
// MIKE_TIMING_SAMPLES=32 go test -run '^TestTimingReview$' -count=1 -v
// MIKE_TIMING_DIT=1 enables the stdlib timing mode for primitive measurements.
// Public key derivation and exchange always enable it in the production API.
func TestTimingReview(t *testing.T) {
	value := os.Getenv("MIKE_TIMING_SAMPLES")
	if value == "" {
		t.Skip("set MIKE_TIMING_SAMPLES to run the timing experiment")
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 2 {
		t.Fatal("MIKE_TIMING_SAMPLES must be an integer >= 2")
	}
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	t.Logf("%s %s/%s, %d samples per class; GC enabled; DIT requested=%t", runtime.Version(), runtime.GOOS, runtime.GOARCH, n, os.Getenv("MIKE_TIMING_DIT") == "1")
	rng := rand.New(rand.NewPCG(0x6d696b65, 0x74696d696e67))
	for set := P308_633; set <= P758_41; set++ {
		t.Run(set.String(), func(t *testing.T) {
			f := allParameters[set]
			peer := decodeHex(t, readParameterVectors(t, set).Keypairs[0].PublicKey)
			sparse := make([]byte, f.secretBytes)
			sparse[0] = 3
			secrets := make([][]byte, n)
			for i := range secrets {
				sk := make([]byte, f.secretBytes)
				for j := range sk {
					sk[j] = byte(rng.Uint32())
				}
				sk[0] = sk[0]&^7 | 3
				sk[len(sk)-1] &= byte((1 << (f.secretBits % 8)) - 1)
				secrets[i] = sk
			}
			for _, operation := range []string{"keygen", "exchange"} {
				t.Run(operation, func(t *testing.T) {
					jobs := make([]timingJob, 0, 2*n)
					for i := range secrets {
						for class, sk := range [][]byte{sparse, secrets[i]} {
							jobs = append(jobs, timingJob{class, func() error {
								if operation == "keygen" {
									pk, err := set.PublicKeyFromSecretKey(sk)
									runtime.KeepAlive(pk)
									return err
								}
								shared, err := set.Exchange(peer, sk)
								runtime.KeepAlive(shared)
								return err
							}})
						}
					}
					measureTiming(t, rng, jobs, 1)
				})
			}
			// Isolate two primitives from the much noisier whole protocol.
			// p-1 is a dense, reduced operand with the same limb count as zero.
			x, y := f.fpSmall(0), f.fpNeg(f.fpSmall(1))
			for _, operation := range []string{"mul", "select"} {
				t.Run(operation, func(t *testing.T) {
					jobs := make([]timingJob, 0, 2*n)
					for i := 0; i < n; i++ {
						for class, operand := range []fp{x, y} {
							jobs = append(jobs, timingJob{class, func() error {
								for j := 0; j < 64; j++ {
									var result fp
									if operation == "mul" {
										result = f.fpMul(operand, y)
									} else {
										result = f.fpSelect(x, y, class)
									}
									runtime.KeepAlive(result)
								}
								return nil
							}})
						}
					}
					measureTiming(t, rng, jobs, 64)
				})
			}
		})
	}
}

type timingJob struct {
	class int
	run   func() error
}

type timingStats struct {
	n        int
	mean, m2 float64
}

func (s *timingStats) add(x float64) {
	s.n++
	delta := x - s.mean
	s.mean += delta / float64(s.n)
	s.m2 += delta * (x - s.mean)
}

func measureTiming(t *testing.T, rng *rand.Rand, jobs []timingJob, batch int) {
	t.Helper()
	// Warm both classes before randomizing balanced measurement order.
	for i := 0; i < 4; i++ {
		if err := jobs[i%2].run(); err != nil {
			t.Fatalf("warmup class %d: %v", i%2, err)
		}
	}
	rng.Shuffle(len(jobs), func(i, j int) { jobs[i], jobs[j] = jobs[j], jobs[i] })
	var stats [2]timingStats
	collect := func() {
		for _, job := range jobs {
			start := time.Now()
			err := job.run()
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("class %d returned an error: %v", job.class, err)
			}
			stats[job.class].add(float64(elapsed.Nanoseconds()) / float64(batch))
		}
	}
	if os.Getenv("MIKE_TIMING_DIT") == "1" {
		// Enter once outside the timed region, so transition cost is excluded.
		subtle.WithDataIndependentTiming(collect)
	} else {
		collect()
	}
	a, b := stats[0], stats[1]
	se := math.Sqrt(a.m2/float64(a.n-1)/float64(a.n) + b.m2/float64(b.n-1)/float64(b.n))
	tValue := "undefined (zero variance)"
	if se != 0 {
		tValue = fmt.Sprintf("%.3f", (a.mean-b.mean)/se)
	}
	t.Logf("n=%d/%d batch=%d mean_ns=%.1f/%.1f raw_t=%s", a.n, b.n, batch, a.mean, b.mean, tValue)
}
