# Performance benchmarks

The suite in [benchmark_test.go](../benchmark_test.go) measures all six sets:

* `GenerateKey`: a fresh pair using `crypto/rand`, including sampling and public
  key derivation.
* `Exchange`: one party's shared-key computation, including peer decoding and
  verification, secret arithmetic, invariant encoding, and SHA3-256. The input
  rotates through six reference exchanges, verified against C outputs before
  measurement. Both peers' exchange calls together cost roughly twice this.

Fixture loading and verification are outside the timer. Go's `B.Loop` manages
timing and keeps calls alive; GC stays enabled. Each result includes ns/op,
ms/op, allocated bytes/op, and allocations/op.

`BenchmarkParameterSets` measures the current API. `BenchmarkParameterSetsDIT`
enters `crypto/subtle.WithDataIndependentTiming` for each call, including its
entry/exit overhead. This is the proposed mitigation from the
[timing review](../TIMING_REVIEW.md), not a claim that the API is constant-time.

```sh
go test -run '^$' -bench '^BenchmarkParameterSets(DIT)?$' \
  -benchmem -cpu 1 -benchtime 3s -count 5 -timeout 15m > benchmarks/local.txt
python3 benchmarks/compare.py benchmarks/local.txt
```

Run on a quiet machine without race, coverage, or fuzz instrumentation. `-cpu 1`
sets `GOMAXPROCS=1`; the suite does not use parallel benchmarks. It does not pin
a performance core, lock clock frequency, or disable turbo. Longer runs are
useful for expensive sets: at a one-second budget the largest exchange only
executes a few times per repetition and may not visit every reference input.

The initial M5 run uses Go 1.27.0, darwin/arm64, an Apple M5 with 24 GB memory,
and the same command with `-benchtime 1s -count 3 -timeout 10m`.
It was collected on 2026-10-06 from commit
`8a43e48880b40b3264e1e4b3b332ca1215ab6184` plus the benchmark changes.
The Go compiler confirms the CPU in the [raw results](m5-go1.27.0.txt).
On this workspace, the command additionally used
`GOCACHE=/private/tmp/mike-go-cache`.

See the [comparison tables](comparison.md). The C numbers are transcribed from
the supplied image: Ryzen 7 PRO 7840U at 3.3 GHz, turbo and multithreading
disabled, with assembly-optimized field arithmetic and no AVX. Our Go port
uses generic pure Go bigmod arithmetic and allocates fresh field values.
Different CPUs, backends, runtime allocation, entropy sources, input samples,
and clock policies mean these ratios compare complete implementations; they
do not measure which CPU has the faster core.

The current Go port on M5 takes about 4–8 times longer for key generation and
5–10 times longer for exchange than the published C numbers. Exchange allocates
56–358 MiB across 1.6–6.2 million objects per call. Those counts make allocation
reduction and the generic field backend useful targets for profiling; these
benchmarks alone do not establish how much time each contributes.

The parser uses Python's standard library and the median of the unrounded
ns/op values. Reproduce the checked-in tables with:

```sh
python3 benchmarks/compare.py benchmarks/m5-go1.27.0.txt > benchmarks/comparison.md
```
