import argparse
import csv
import math
import statistics
from pathlib import Path


ALGORITHMS = ("ascon", "aes-gcm")
METRICS = (
    "encrypt_us_per_packet",
    "decrypt_us_per_packet",
    "encrypt_mib_per_s",
    "decrypt_mib_per_s",
)


def read_run(path):
    with path.open(newline="", encoding="utf-8-sig") as source:
        rows = list(csv.DictReader(source))

    groups = {algorithm: [] for algorithm in ALGORITHMS}

    for row in rows:
        algorithm = row["algorithm"]

        if algorithm not in groups:
            raise ValueError(f"{path.name}: unknown algorithm")

        if (
            int(row["payload_bytes"]) != 128
            or int(row["iterations"]) != 1000
        ):
            raise ValueError(f"{path.name}: unexpected configuration")

        for metric in METRICS:
            value = float(row[metric])

            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{path.name}: invalid {metric}")

            row[metric] = value

        groups[algorithm].append(row)

    means = {}

    for algorithm, records in groups.items():
        rounds = sorted(int(row["round"]) for row in records)

        if rounds != list(range(1, 31)):
            raise ValueError(
                f"{path.name}: {algorithm} requires rounds 1-30"
            )

        means[algorithm] = {
            metric: statistics.mean(
                row[metric] for row in records
            )
            for metric in METRICS
        }

    return means


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(
            destination,
            fieldnames=list(rows[0]),
        )
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(
        description="Summarize five separate crypto benchmark runs."
    )
    parser.add_argument("results_dir", type=Path)
    args = parser.parse_args()

    runs = []
    run_rows = []

    # Explicit filenames exclude the individual summary CSV files.
    for run_number in range(1, 6):
        path = args.results_dir / f"run_{run_number}.csv"
        means = read_run(path)
        runs.append(means)

        row = {"run": run_number}

        for algorithm in ALGORITHMS:
            for metric in METRICS:
                row[f"{algorithm}_{metric}"] = means[algorithm][metric]

        for operation in ("encrypt", "decrypt"):
            metric = f"{operation}_us_per_packet"
            row[f"{operation}_speedup"] = (
                means["aes-gcm"][metric] / means["ascon"][metric]
            )

        run_rows.append(row)

    aggregate_rows = []

    for algorithm in ALGORITHMS:
        for metric in METRICS:
            values = [run[algorithm][metric] for run in runs]
            mean = statistics.mean(values)
            stdev = statistics.stdev(values)

            aggregate_rows.append({
                "algorithm": algorithm,
                "metric": metric,
                "runs": len(values),
                "mean_of_run_means": mean,
                "stdev_of_run_means": stdev,
                "cv_percent": stdev / mean * 100,
                "min_run_mean": min(values),
                "max_run_mean": max(values),
            })

    comparison_rows = []

    for operation in ("encrypt", "decrypt"):
        metric = f"{operation}_us_per_packet"
        ascon_mean = statistics.mean(
            run["ascon"][metric] for run in runs
        )
        aes_mean = statistics.mean(
            run["aes-gcm"][metric] for run in runs
        )

        comparison_rows.append({
            "operation": operation,
            "ascon_mean_us": ascon_mean,
            "aes_gcm_mean_us": aes_mean,
            "ratio_of_mean_latencies": aes_mean / ascon_mean,
            "min_run_speedup": min(
                row[f"{operation}_speedup"] for row in run_rows
            ),
            "max_run_speedup": max(
                row[f"{operation}_speedup"] for row in run_rows
            ),
        })

    write_csv(args.results_dir / "runs_summary.csv", run_rows)
    write_csv(args.results_dir / "aggregate_summary.csv", aggregate_rows)
    write_csv(args.results_dir / "comparison_summary.csv", comparison_rows)

    print("Per-run mean latency (microseconds/packet):")
    print("Run | Ascon enc | AES enc | Ascon dec | AES dec")

    for row in run_rows:
        print(
            f"{row['run']:3} | "
            f"{row['ascon_encrypt_us_per_packet']:.4f} | "
            f"{row['aes-gcm_encrypt_us_per_packet']:.4f} | "
            f"{row['ascon_decrypt_us_per_packet']:.4f} | "
            f"{row['aes-gcm_decrypt_us_per_packet']:.4f}"
        )

    print("\nAcross-run latency statistics:")

    for row in aggregate_rows:
        if row["metric"].endswith("us_per_packet"):
            print(
                f"{row['algorithm']:8} {row['metric']:24} | "
                f"mean={row['mean_of_run_means']:.4f} | "
                f"stdev={row['stdev_of_run_means']:.4f} | "
                f"CV={row['cv_percent']:.2f}%"
            )

    print("\nSpeedup (ratio of mean latencies):")

    for row in comparison_rows:
        print(
            f"{row['operation']}: "
            f"{row['ratio_of_mean_latencies']:.2f}x "
            f"(per-run range: "
            f"{row['min_run_speedup']:.2f}-"
            f"{row['max_run_speedup']:.2f}x)"
        )

    print(f"\nThree summary CSV files saved to: {args.results_dir}")


if __name__ == "__main__":
    main()