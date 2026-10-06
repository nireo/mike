#!/usr/bin/env python3
"""Regenerate p308_633 vectors with the supplied C reference (requires clang).

The C ec_ladder3pt definition incorrectly says void despite its int declaration
and return values. Only that return type is corrected in the temporary copy.
No reference source files are modified. Normal Go tests need neither C nor Python.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
C = ROOT / "mike_c"


def functions(path, names):
    source = (C / path).read_text()
    result = []
    for name in names:
        match = re.search(r"(?:void|int|uint32_t)\s*\n" + name + r"\(", source)
        if match is None:
            raise ValueError(name)
        opening = source.index("{", match.end())
        depth = 1
        end = opening + 1
        while depth:
            depth += (source[end] == "{") - (source[end] == "}")
            end += 1
        function = source[match.start():end]
        if name == "ec_ladder3pt":
            function = function.replace("void\n", "int\n", 1)
        result.append(function)
    return "\n".join(result)


HARNESS = r'''
#include <nike.h>
#include <ec_isog.h>
#include <rng.h>
#include <e0_basis.h>
static unsigned char seed[SECRETKEY_BYTES];
int randombytes(unsigned char *out, unsigned long long len) {
    assert(len == sizeof(seed));
    memcpy(out, seed, len);
    return 0;
}
static void print_hex(const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    puts("");
}
int main(int argc, char **argv) {
    if ((argc != 2 && argc != 3) || strlen(argv[1]) != 2 * sizeof(seed)) return 1;
    for (size_t i = 0; i < sizeof(seed); i++) {
        unsigned value;
        if (sscanf(argv[1] + 2*i, "%2x", &value) != 1) return 1;
        seed[i] = value;
    }
    unsigned char buf[FP2_ENCODED_BYTES];
    const fp_t *constants[] = { &A0, &BASIS_sk_PX.re, &BASIS_sk_QX.re,
        &BASIS_sk_PMQX.re, &BASIS_sk_PMQX.im };
    for (int i = 0; i < 5; i++) {
        fp_encode(buf, constants[i]);
        print_hex(buf, FP_ENCODED_BYTES);
    }
    public_key_t pk;
    secret_key_t sk;
    if (!protocols_keygen(&pk, &sk)) return 2;
    secret_key_to_bytes(buf, &sk);
    print_hex(buf, SECRETKEY_BYTES);
    public_key_to_bytes(buf, &pk);
    print_hex(buf, PUBLICKEY_BYTES);
    shared_t shared;
    for (int i = 0; i < 4; i++) fp_copy(&shared.invariant[i], constants[i]);
    for (int i = 0; i < 4; i++) {
        fp_encode(buf, &shared.invariant[i]);
        print_hex(buf, FP_ENCODED_BYTES);
    }
    hash_shared_secret(buf, &shared);
    print_hex(buf, SHARED_BYTES);
    if (argc == 3) {
        unsigned char peer_bytes[PUBLICKEY_BYTES];
        if (strlen(argv[2]) != 2 * sizeof(peer_bytes)) return 1;
        for (size_t i = 0; i < sizeof(peer_bytes); i++) {
            unsigned value;
            if (sscanf(argv[2] + 2*i, "%2x", &value) != 1) return 1;
            peer_bytes[i] = value;
        }
        public_key_t peer;
        if (!public_key_from_bytes(&peer, peer_bytes)) return 3;
        if (!protocols_exchange(&shared, &peer, &sk)) return 3;
        for (int i = 0; i < 4; i++) {
            fp_encode(buf, &shared.invariant[i]);
            print_hex(buf, FP_ENCODED_BYTES);
        }
        hash_shared_secret(buf, &shared);
        print_hex(buf, SHARED_BYTES);
    }
    return 0;
}
'''


def main():
    includes = ["include", "src/common/generic/include", "src/gf/ref/include",
                "src/precomp/ref/p308_633/include", "src/ec/ref/include",
                "src/theta/ref/include", "src/weil/ref/include", "src/nike/ref/include"]
    sources = ["src/gf/ref/p308_633/fp_p308_633.c", "src/gf/ref/lvlx/fp.c",
               "src/gf/ref/lvlx/fp2.c", "src/precomp/ref/p308_633/constants.c",
               "src/precomp/ref/p308_633/e0_basis.c", "src/ec/ref/lvlx/normalize.c",
               "src/nike/ref/lvlx/keygen.c", "src/nike/ref/lvlx/encode.c",
               "src/common/generic/fips202.c", "src/ec/ref/lvlx/basis.c",
               "src/precomp/ref/p308_633/ec_params.c", "src/nike/ref/lvlx/exchange.c"]
    sources += [str(p.relative_to(C)) for module in ["theta", "weil"]
                for p in sorted((C / f"src/{module}/ref/lvlx").glob("*.c"))]
    selected = (C / "src/ec/ref/lvlx/ec.c").read_text()
    selected = re.sub(r"void\s*\nec_ladder3pt", "int\nec_ladder3pt", selected)
    selected = "#include <ec_isog.h>\n" + selected
    selected += "\n" + functions("src/ec/ref/lvlx/isog_chains.c", [
        "ec_xDBL_A24", "ec_iso_xisog_4", "ec_iso_xeval_4",
        "ec_iso_isogeny_2chain_with_strategy", "ec_iso_isogeny_2chain"])
    seeds = [bytes(29), bytes([255])*29, bytes(range(29))]
    seeds += [hashlib.sha256(f"MIKE Go vector {i}".encode()).digest()[:29] for i in range(5)]
    vectors = []
    exchanges = []
    with tempfile.TemporaryDirectory(prefix="mike-vectors-") as temp:
        temp = Path(temp)
        (temp / "ec.c").write_text(selected)
        (temp / "oracle.c").write_text(HARNESS)
        command = ["clang", "-O2", "-DNDEBUG", "-DRADIX_64", "-DDISABLE_NAMESPACING"]
        command += ["-I" + str(C / p) for p in includes]
        command += [str(C / p) for p in sources]
        command += [str(temp / "ec.c"), str(temp / "oracle.c"), "-o", str(temp / "oracle")]
        subprocess.run(command, check=True)
        for seed in seeds:
            lines = subprocess.check_output([str(temp / "oracle"), seed.hex()], text=True).splitlines()
            vectors.append({"seed": seed.hex(), "secret_key": lines[5], "public_key": lines[6]})
        constants_lines = lines
        for alice, bob in [(0, 1), (0, 2), (2, 3), (4, 5), (6, 7), (3, 3)]:
            lines = subprocess.check_output([str(temp / "oracle"), seeds[alice].hex(),
                                             vectors[bob]["public_key"]], text=True).splitlines()
            reverse = subprocess.check_output([str(temp / "oracle"), seeds[bob].hex(),
                                               vectors[alice]["public_key"]], text=True).splitlines()
            if lines[12:] != reverse[12:]:
                raise ValueError("C reference parties disagree")
            exchanges.append({"alice": alice, "bob": bob, "invariants": "".join(lines[12:16]),
                              "shared_secret": lines[16]})
    lines = constants_lines
    output = {"parameter_set": "p308_633", "constants": dict(zip(
        ["a0", "basis_p", "basis_q", "basis_p_minus_q_re", "basis_p_minus_q_im"], lines[:5])),
        "keypairs": vectors, "invariants": "".join(lines[7:11]), "shared_hash": lines[11],
        "exchanges": exchanges}
    (ROOT / "testdata/p308_633.json").write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
