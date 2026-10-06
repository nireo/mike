// SPDX-License-Identifier: Apache-2.0

package mike

// Canonical little-endian values of A0 and BASIS_sk_* from the C precomputation.
// Unlike the C limb arrays, these are independent of radix and Montgomery form.
// Regenerate with testdata/generate_vectors.py; see testdata/p308_633.json.
var (
	curveA   = fp2{mustFP("def6e76e68069827513779218a11830e5915ea48ae21816ab17e6d720e41de60a5f64591ea3daa10"), fpSmall(0)}
	curveA24 = fp2Mul(fp2Add(curveA, fp2Small(2)), fp2Inv(fp2Small(4)))
	basisP   = ecPoint{fp2{mustFP("821354db1ea1337ae966ce69fccfc8a5d377c8869584a1fe0b3f3a3caf2f28b72806b3905941ba24"), fpSmall(0)}, fp2Small(1)}
	basisQ   = ecPoint{fp2{mustFP("e84711304605676be01e36d5fccedfa59b2446f3a00fb30fd3c17c779c4feeb21300c9635f95491f"), fpSmall(0)}, fp2Small(1)}
	basisPmQ = ecPoint{fp2{
		mustFP("b5adb2853253cdf2e442829f7c4fd4a5374e073d1b4a2a876f80dbd9a53f0b351e033e7a5ceb0122"),
		mustFP("f36b7f781a1a13e08abe97f8159b6f2f247ce055e4a1ce2e59950af377bcf6baa3670a9bd2d59f11"),
	}, fp2Small(1)}
)

func mustFP(s string) fp {
	x, err := fpDecode(mustHex(s))
	if err != nil {
		panic(err)
	}
	return x
}
