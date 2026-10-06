#!/usr/bin/env python3
"""Print median Go timings beside the C numbers in the supplied performance table."""

import argparse
from collections import defaultdict
from pathlib import Path
import re
from statistics import median


# Fast, then rigorous, in NIST I/III/V order. C measurements are from the
# user-supplied image: Ryzen 7 PRO 7840U at 3.3 GHz, turbo and SMT disabled.
REFERENCE = [
    ("Fast I", "p308_633", 0.651, 4.86),
    ("Fast III", "p474_593", 2.11, 15.0),
    ("Fast V", "p628_317", 4.16, 28.6),
    ("Rigorous I", "p374_117", 1.49, 10.5),
    ("Rigorous III", "p566_77", 4.55, 31.3),
    ("Rigorous V", "p758_41", 11.2, 69.9),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path, help="complete Go benchmark output")
    args = parser.parse_args()
    text = args.results.read_text()
    if "PASS" not in text.splitlines():
        parser.error("benchmark output must contain a successful PASS line")

    samples = defaultdict(list)
    name_pattern = re.compile(
        r"^BenchmarkParameterSets(DIT)?/(p\d+_\d+)/(GenerateKey|Exchange)(?:-\d+)?$"
    )
    for line in text.splitlines():
        columns = line.split()
        if not columns or not (match := name_pattern.match(columns[0])):
            continue
        if len(columns) < 4:
            continue  # A benchmark name printed before its measurement.
        metrics = {unit: float(value) for value, unit in zip(columns[2::2], columns[3::2])}
        if "ns/op" in metrics:
            mode, parameter_set, operation = match.groups()
            samples[(bool(mode), parameter_set, operation)].append(metrics)

    for _, parameter_set, _, _ in REFERENCE:
        for dit in (False, True):
            for operation in ("GenerateKey", "Exchange"):
                if not samples[(dit, parameter_set, operation)]:
                    parser.error(f"missing measurements: DIT={dit}, {parameter_set}/{operation}")

    def value(dit, parameter_set, operation, metric):
        return median(s[metric] for s in samples[(dit, parameter_set, operation)])

    print("All times are milliseconds per API call; Go values are medians of repeated runs.\n")
    print("| Group | Set | C keygen | Go keygen | Go DIT keygen | C exchange | Go exchange | Go DIT exchange |")
    print("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for group, parameter_set, keygen, exchange in REFERENCE:
        go = [value(dit, parameter_set, op, "ns/op") / 1e6 for op in ("GenerateKey", "Exchange") for dit in (False, True)]
        print(f"| {group} | {parameter_set} | {keygen:g} | {go[0]:.3f} | {go[1]:.3f} | {exchange:g} | {go[2]:.3f} | {go[3]:.3f} |")

    print("\nAllocations below are for the default API; MiB/op counts total bytes allocated, not peak memory.\n")
    print("| Set | Keygen MiB/op | Keygen allocs/op | Exchange MiB/op | Exchange allocs/op |")
    print("| --- | ---: | ---: | ---: | ---: |")
    for _, parameter_set, _, _ in REFERENCE:
        metrics = [value(False, parameter_set, op, metric) for op in ("GenerateKey", "Exchange") for metric in ("B/op", "allocs/op")]
        print(f"| {parameter_set} | {metrics[0] / 2**20:.2f} | {metrics[1]:,.0f} | {metrics[2] / 2**20:.2f} | {metrics[3]:,.0f} |")


if __name__ == "__main__":
    main()
