import argparse
import csv
import re
import statistics
from pathlib import Path

from summarize_repeats import read_run, write_csv


MODES = ("per_packet", "session")
OPERATIONS = ("encrypt", "decrypt")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze six paired crypto benchmark runs."
    )
    parser.add_argument("results_dir", type=Path)
    args = parser.parse_args()

    with (args.results_dir / "manifest.csv").open(
        newline="", encoding="utf-8-sig"
    ) as source:
        manifest = list(csv.DictReader(source))

    expected_keys = {
        (pair, mode)
        for pair in range(1, 7)
        for mode in MODES
    }

    actual_keys = [
        (int(row["pair"]), row["mode"])
        for row in manifest
    ]

    if len(actual_keys) != 12 or set(actual_keys) != expected_keys:
        raise ValueError("Manifest must contain six complete pairs.")

    for mode in MODES:
        hashes = {
            row["executable_sha256"].lower()
            for row in manifest
            if row["mode"] == mode
        }

        if len(hashes) != 1:
            raise ValueError(f"{mode}: executable changed between runs.")

        if not re.fullmatch(r"[0-9a-f]{64}", next(iter(hashes))):
            raise ValueError(f"{mode}: invalid executable hash.")

    runs = {}

    for row in manifest:
        pair = int(row["pair"])
        mode = row["mode"]

        expected_order = (
            ("per_packet", "session")
            if pair % 2 == 1
            else ("session", "per_packet")
        )

        if int(row["position"]) != expected_order.index(mode) + 1:
            raise ValueError(f"Pair {pair}: unexpected run order.")

        expected_name = f"pair_{pair}_{mode}.csv"

        if row["csv_file"] != expected_name:
            raise ValueError(f"Unexpected CSV filename: {row['csv_file']}")

        runs[(pair, mode)] = read_run(
            args.results_dir / expected_name
        )

    comparisons = []

    for pair in range(1, 7):
        per_packet = runs[(pair, "per_packet")]
        session = runs[(pair, "session")]

        for operation in OPERATIONS:
            metric = f"{operation}_us_per_packet"

            aes_before = per_packet["aes-gcm"][metric]
            aes_after = session["aes-gcm"][metric]
            ascon_before = per_packet["ascon"][metric]
            ascon_after = session["ascon"][metric]

            comparisons.append({
                "pair": pair,
                "operation": operation,
                "aes_per_packet_us": aes_before,
                "aes_session_us": aes_after,
                "aes_reduction_us": aes_before - aes_after,
                "aes_reduction_percent": (
                    (aes_before - aes_after) / aes_before * 100
                ),
                "ascon_per_packet_us": ascon_before,
                "ascon_session_us": ascon_after,
                "ascon_change_percent": (
                    (ascon_after - ascon_before) / ascon_before * 100
                ),
                "ascon_speedup_per_packet": aes_before / ascon_before,
                "ascon_speedup_session": aes_after / ascon_after,
            })

    aggregates = []

    for operation in OPERATIONS:
        records = [
            row for row in comparisons
            if row["operation"] == operation
        ]

        for field in records[0]:
            if field in ("pair", "operation"):
                continue

            values = [row[field] for row in records]

            aggregates.append({
                "operation": operation,
                "metric": field,
                "pairs": len(values),
                "mean": statistics.mean(values),
                "stdev": statistics.stdev(values),
                "min": min(values),
                "max": max(values),
            })

    write_csv(
        args.results_dir / "paired_comparisons.csv",
        comparisons,
    )
    write_csv(
        args.results_dir / "paired_aggregate.csv",
        aggregates,
    )

    print("AES latency reduction: per-packet -> session")
    print("Pair | Operation | Before us | After us | Reduction % | Ascon change %")

    for row in comparisons:
        print(
            f"{row['pair']:4} | "
            f"{row['operation']:9} | "
            f"{row['aes_per_packet_us']:.4f} | "
            f"{row['aes_session_us']:.4f} | "
            f"{row['aes_reduction_percent']:+.2f}% | "
            f"{row['ascon_change_percent']:+.2f}%"
        )

    print("\nAcross-pair reduction statistics:")

    for row in aggregates:
        if row["metric"] == "aes_reduction_percent":
            print(
                f"{row['operation']}: "
                f"mean={row['mean']:.2f}% | "
                f"stdev={row['stdev']:.2f} percentage points | "
                f"range={row['min']:.2f}-{row['max']:.2f}%"
            )

    print("\nReduction includes possible system-condition differences.")
    print(f"Results saved to: {args.results_dir}")


if __name__ == "__main__":
    main()