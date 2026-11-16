import argparse
import csv
import itertools
import math
import statistics
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parent
MODES = ("none", "ascon", "aes-gcm")
METRICS = (
    "transfer",
    "receiver_processing",
    "packet_ready",
    "window_start_to_ready",
)


def read_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(
            destination,
            fieldnames=list(rows[0]),
        )
        writer.writeheader()
        writer.writerows(rows)


def metric_stats(values):
    return {
        "mean": statistics.mean(values),
        "p95": float(np.percentile(values, 95)),
        "max": max(values),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Validate and summarize streaming experiments."
    )
    parser.add_argument("series_dir", type=Path)
    args = parser.parse_args()

    series_dir = args.series_dir.resolve()
    manifest = read_csv(series_dir / "manifest.csv")

    expected_orders = list(itertools.permutations(MODES))
    expected_keys = {
        (repetition, mode)
        for repetition in range(1, 7)
        for mode in MODES
    }

    actual_keys = [
        (int(row["repetition"]), row["crypto_mode"])
        for row in manifest
    ]

    if len(manifest) != 18 or set(actual_keys) != expected_keys:
        raise ValueError("Expected six complete repetitions of three modes.")

    if len({row["dll_sha256"] for row in manifest}) != 1:
        raise ValueError("Recorded DLL hashes are inconsistent.")

    experiment_paths = set()
    run_rows = []
    pooled_windows = {mode: [] for mode in MODES}

    for entry in manifest:
        repetition = int(entry["repetition"])
        mode = entry["crypto_mode"]
        position = int(entry["position"])

        expected_position = (
            expected_orders[repetition - 1].index(mode) + 1
        )

        if position != expected_position:
            raise ValueError("Unexpected mode order in manifest.")

        experiment_dir = (ROOT / entry["experiment_dir"]).resolve()

        if not experiment_dir.is_relative_to(ROOT / "results"):
            raise ValueError("Experiment path is outside results.")

        if experiment_dir in experiment_paths:
            raise ValueError("An experiment directory was reused.")

        experiment_paths.add(experiment_dir)

        summaries = read_csv(experiment_dir / "summary.csv")
        receiver = read_csv(experiment_dir / "receiver_packets.csv")

        if len(summaries) != 1:
            raise ValueError(f"{experiment_dir.name}: invalid summary")

        summary = summaries[0]

        if (
            summary["test_passed"] != "True"
            or summary["crypto_mode"] != mode
            or int(summary["test_mode"]) != 0
            or int(summary["planned_packets"]) != 80
            or int(summary["actual_udp_sends"]) != 80
            or int(summary["received_datagrams"]) != 80
            or int(summary["accepted_unique_packets"]) != 80
            or float(summary["window_ms"]) != 62.5
        ):
            raise ValueError(f"{experiment_dir.name}: unexpected configuration")

        if (
            len(receiver) != 80
            or any(row["status"] != "accepted" for row in receiver)
            or sorted(int(row["sequence"]) for row in receiver)
            != list(range(80))
        ):
            raise ValueError(f"{experiment_dir.name}: invalid packet records")

        run = {
            "repetition": repetition,
            "position": position,
            "crypto_mode": mode,
            "run_id": summary["run_id"],
            "accepted_packets": len(receiver),
        }

        for metric in METRICS:
            values = [
                float(row[f"{metric}_ms"])
                for row in receiver
            ]

            if any(not math.isfinite(v) or v < 0 for v in values):
                raise ValueError(f"Invalid latency: {metric}")

            for stat, value in metric_stats(values).items():
                field = f"{metric}_{stat}_ms"

                if not math.isclose(
                    value,
                    float(summary[field]),
                    rel_tol=1e-9,
                    abs_tol=1e-6,
                ):
                    raise ValueError(
                        f"{experiment_dir.name}: inconsistent {field}"
                    )

                run[field] = value

        for packet in receiver:
            expected_window_ms = (
                62.5
                + float(packet["pre_encrypt_schedule_offset_ms"])
                + float(packet["packet_ready_ms"])
            )

            if not math.isclose(
                float(packet["window_start_to_ready_ms"]),
                expected_window_ms,
                rel_tol=1e-9,
                abs_tol=1e-6,
            ):
                raise ValueError("Window latency identity failed.")

        window_values = [
            float(row["window_start_to_ready_ms"])
            for row in receiver
        ]

        run["window_over_100_ms_packets"] = sum(
            value > 100.0 for value in window_values
        )

        pooled_windows[mode].extend(window_values)
        run_rows.append(run)

    mode_rows = []

    for mode in MODES:
        records = [
            row for row in run_rows
            if row["crypto_mode"] == mode
        ]

        aggregate = {
            "crypto_mode": mode,
            "runs": len(records),
            "accepted_packets": sum(
                row["accepted_packets"] for row in records
            ),
        }

        for metric in METRICS:
            means = [
                row[f"{metric}_mean_ms"] for row in records
            ]

            aggregate[f"{metric}_mean_of_run_means_ms"] = (
                statistics.mean(means)
            )
            aggregate[f"{metric}_stdev_of_run_means_ms"] = (
                statistics.stdev(means)
            )
            aggregate[f"{metric}_mean_of_run_p95_ms"] = (
                statistics.mean(
                    row[f"{metric}_p95_ms"] for row in records
                )
            )
            aggregate[f"{metric}_worst_packet_ms"] = max(
                row[f"{metric}_max_ms"] for row in records
            )

        # Descriptive percentile of all 480 measured packets.
        # This does not treat them as independent experiment repeats.
        aggregate["window_start_to_ready_pooled_p95_ms"] = float(
            np.percentile(pooled_windows[mode], 95)
        )

        aggregate["window_over_100_ms_packets"] = sum(
            row["window_over_100_ms_packets"] for row in records
        )

        aggregate["window_over_100_ms_percent"] = (
            aggregate["window_over_100_ms_packets"]
            / aggregate["accepted_packets"]
            * 100
        )

        mode_rows.append(aggregate)

    write_csv(
        series_dir / "streaming_runs_summary.csv",
        run_rows,
    )
    write_csv(
        series_dir / "streaming_modes_summary.csv",
        mode_rows,
    )

    print("Mode | Runs | Packets | Ready mean ms | Window mean ms | >100 ms")

    for row in mode_rows:
        print(
            f"{row['crypto_mode']:7} | "
            f"{row['runs']} | "
            f"{row['accepted_packets']} | "
            f"{row['packet_ready_mean_of_run_means_ms']:.4f} | "
            f"{row['window_start_to_ready_mean_of_run_means_ms']:.4f} | "
            f"{row['window_over_100_ms_packets']}"
        )

    print(f"\nTwo summary CSV files saved to: {series_dir}")


if __name__ == "__main__":
    main()