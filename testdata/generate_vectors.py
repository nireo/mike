#!/usr/bin/env python3
"""Regenerate all parameter sets and vectors with the C reference (needs clang).

The C ec_ladder3pt definition incorrectly says void despite its int declaration
and return values. Only that return type is corrected in the temporary copy.
No reference source files are modified. Normal Go tests need neither C nor Python.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
C = ROOT / "mike_c"
SETS = ["p308_633", "p374_117", "p474_593", "p566_77", "p628_317", "p758_41"]


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
    fp_encode(buf, &BASIS_sk_PX.im);
    print_hex(buf, FP_ENCODED_BYTES);
    fp_encode(buf, &BASIS_sk_QX.im);
    print_hex(buf, FP_ENCODED_BYTES);
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


def generate(name):
    precomp = C / f"src/precomp/ref/{name}"
    sizes = {k: int(v) for k, v in re.findall(r"#define (\w+) (\d+)",
                                             (precomp / "include/encoded_sizes.h").read_text())}
    torsion, cofactor = map(int, name[1:].split("_"))
    secret_size = sizes["SECRETKEY_BYTES"]
    includes = ["include", "src/common/generic/include", "src/gf/ref/include",
                f"src/precomp/ref/{name}/include", "src/ec/ref/include",
                "src/theta/ref/include", "src/weil/ref/include", "src/nike/ref/include"]
    sources = [f"src/gf/ref/{name}/fp_{name}.c", "src/gf/ref/lvlx/fp.c",
               "src/gf/ref/lvlx/fp2.c", f"src/precomp/ref/{name}/constants.c",
               f"src/precomp/ref/{name}/e0_basis.c", "src/ec/ref/lvlx/normalize.c",
               "src/nike/ref/lvlx/keygen.c", "src/nike/ref/lvlx/encode.c",
               "src/common/generic/fips202.c", "src/ec/ref/lvlx/basis.c",
               f"src/precomp/ref/{name}/ec_params.c", "src/nike/ref/lvlx/exchange.c"]
    sources += [str(p.relative_to(C)) for module in ["theta", "weil"]
                for p in sorted((C / f"src/{module}/ref/lvlx").glob("*.c"))]
    selected = (C / "src/ec/ref/lvlx/ec.c").read_text()
    selected = re.sub(r"void\s*\nec_ladder3pt", "int\nec_ladder3pt", selected)
    selected = "#include <ec_isog.h>\n" + selected
    selected += "\n" + functions("src/ec/ref/lvlx/isog_chains.c", [
        "ec_xDBL_A24", "ec_iso_xisog_4", "ec_iso_xeval_4",
        "ec_iso_isogeny_2chain_with_strategy", "ec_iso_isogeny_2chain"])
    seeds = [bytes(secret_size), bytes([255])*secret_size, bytes(range(secret_size))]
    for i in range(5):
        tag = f"MIKE Go vector {i}".encode()
        seed = hashlib.sha256(tag).digest()
        for j in range(1, (secret_size + 31) // 32):
            seed += hashlib.sha256(tag + f" block {j}".encode()).digest()
        seeds.append(seed[:secret_size])
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
            if lines[14:] != reverse[14:]:
                raise ValueError("C reference parties disagree")
            exchanges.append({"alice": alice, "bob": bob, "invariants": "".join(lines[14:18]),
                              "shared_secret": lines[18]})
    lines = constants_lines
    metadata = {"security_bits": sizes["SECURITY_BITS"], "field_bytes": sizes["FP_ENCODED_BYTES"],
                "secret_bits": sizes["SECRETKEY_BITS"], "chain_length": sizes["SECRETKEY_CHAIN_LENGTH"],
                "hd_margin": sizes["HD_MARGIN"], "torsion_power": torsion, "cofactor": cofactor}
    output = {"parameter_set": name, "parameters": metadata, "constants": dict(zip(
        ["a0", "basis_p", "basis_q", "basis_p_minus_q_re", "basis_p_minus_q_im"], lines[:5])),
        "keypairs": vectors, "invariants": "".join(lines[7:11]), "shared_hash": lines[11],
        "exchanges": exchanges}
    output["constants"].update(basis_p_im=lines[12], basis_q_im=lines[13])
    (ROOT / f"testdata/{name}.json").write_text(json.dumps(output, indent=2) + "\n")
    print(f"Generated {name}: 8 key pairs, 6 exchanges", flush=True)


def generate_go_constants():
    lines = ["// SPDX-License-Identifier: Apache-2.0", "",
             "// Code generated by testdata/generate_vectors.py; DO NOT EDIT.", "", "package mike", "",
             "var allParameters = [...]*parameters{"]
    for name in SETS:
        vector = json.loads((ROOT / f"testdata/{name}.json").read_text())
        p = vector["parameters"]
        args = [json.dumps(name)] + [str(p[k]) for k in ["security_bits", "field_bytes", "secret_bits",
                                                       "chain_length", "hd_margin", "torsion_power", "cofactor"]]
        lines.append("\tnewParameters(" + ", ".join(args) + ",")
        for key in ["a0", "basis_p", "basis_p_im", "basis_q", "basis_q_im", "basis_p_minus_q_re", "basis_p_minus_q_im"]:
            lines.append("\t\t" + json.dumps(vector["constants"][key]) + ",")
        lines.append("\t),")
    lines.append("}")
    (ROOT / "params_generated.go").write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sets", nargs="*", choices=SETS)
    args = parser.parse_args()
    for name in args.sets or SETS:
        generate(name)
    generate_go_constants()


if __name__ == "__main__":
    main()
