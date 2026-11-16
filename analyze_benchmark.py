import argparse
import csv
import math
import statistics
from pathlib import Path


METRICS = (
    "encrypt_us_per_packet",
    "decrypt_us_per_packet",
    "encrypt_mib_per_s",
    "decrypt_mib_per_s",
)


def main():
    parser = argparse.ArgumentParser(
        description="Summarize crypto benchmark rounds."
    )
    parser.add_argument("csv_path", type=Path)
    args = parser.parse_args()

    # utf-8-sig also handles the BOM produced by Windows PowerShell.
    with args.csv_path.open(
        newline="", encoding="utf-8-sig"
    ) as source:
        rows = list(csv.DictReader(source))

    groups = {"ascon": [], "aes-gcm": []}

    for row in rows:
        algorithm = row["algorithm"]

        if algorithm not in groups:
            raise ValueError(f"Unknown algorithm: {algorithm}")

        if int(row["payload_bytes"]) != 128:
            raise ValueError("Expected 128-byte payloads")

        if int(row["iterations"]) != 1000:
            raise ValueError("Expected 1000 iterations per round")

        for metric in METRICS:
            value = float(row[metric])

            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"Invalid {metric}: {value}")

            row[metric] = value

        groups[algorithm].append(row)

    summaries = []

    for algorithm, records in groups.items():
        rounds = [int(row["round"]) for row in records]

        if sorted(rounds) != list(range(1, 31)):
            raise ValueError(
                f"{algorithm}: expected rounds 1-30 exactly once"
            )

        for metric in METRICS:
            values = [row[metric] for row in records]

            summaries.append({
                "algorithm": algorithm,
                "metric": metric,
                "rounds": len(values),
                "mean": statistics.mean(values),
                "median": statistics.median(values),
                "stdev": statistics.stdev(values),
                "min": min(values),
                "max": max(values),
            })

    output_path = args.csv_path.with_name(
        f"{args.csv_path.stem}_summary.csv"
    )

    with output_path.open(
        "w", newline="", encoding="utf-8"
    ) as destination:
        writer = csv.DictWriter(
            destination,
            fieldnames=list(summaries[0]),
        )
        writer.writeheader()
        writer.writerows(summaries)

    print("Latency across batch averages (microseconds/packet):")

    for row in summaries:
        if row["metric"].endswith("us_per_packet"):
            operation = row["metric"].split("_")[0]

            print(
                f"{row['algorithm']:8} {operation:7} | "
                f"mean={row['mean']:.4f} | "
                f"median={row['median']:.4f} | "
                f"stdev={row['stdev']:.4f}"
            )

    print("\nSpeedup from mean latency (AES-GCM / Ascon):")

    for metric in METRICS[:2]:
        means = {
            row["algorithm"]: row["mean"]
            for row in summaries
            if row["metric"] == metric
        }

        ratio = means["aes-gcm"] / means["ascon"]
        print(f"{metric}: {ratio:.2f}x")

    print(f"\nSummary saved to: {output_path}")


if __name__ == "__main__":
    main()