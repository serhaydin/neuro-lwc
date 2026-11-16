import csv
import hashlib
import itertools
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


ROOT = Path(__file__).resolve().parent
MODES = ("none", "ascon", "aes-gcm")


def main():
    run_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
        + "_"
        + uuid4().hex[:8]
    )

    output_dir = ROOT / "results" / f"streaming_repeats_{run_id}"
    output_dir.mkdir(parents=True, exist_ok=False)

    dll_path = ROOT / "cmake-build-debug" / "neuro_crypto.dll"
    dll_hash = hashlib.sha256(dll_path.read_bytes()).hexdigest()

    manifest = []

    for repetition, order in enumerate(
        itertools.permutations(MODES),
        start=1,
    ):
        for position, mode in enumerate(order, start=1):
            name = f"repeat_{repetition}_{mode}"
            log_path = output_dir / f"{name}.log"
            started_at = datetime.now(timezone.utc).isoformat()

            print(
                f"Repeat {repetition}/6, position {position}: {mode}",
                flush=True,
            )

            with log_path.open("w", encoding="utf-8") as log:
                result = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "data_flow_simulation.py"),
                        "--crypto-mode",
                        mode,
                        "--test-mode",
                        "0",
                    ],
                    cwd=ROOT,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=60,
                    check=False,
                )

            if result.returncode != 0:
                raise RuntimeError(
                    f"{name} failed. Inspect {log_path}"
                )

            lines = log_path.read_text(encoding="utf-8").splitlines()
            paths = [
                line.removeprefix("Results saved to: ").strip()
                for line in lines
                if line.startswith("Results saved to: ")
            ]

            if len(paths) != 1:
                raise RuntimeError(f"{name}: result directory not found")

            experiment_dir = Path(paths[0])

            if not experiment_dir.is_absolute():
                experiment_dir = ROOT / experiment_dir

            experiment_dir = experiment_dir.resolve()

            if not experiment_dir.is_relative_to(ROOT / "results"):
                raise RuntimeError("Unexpected experiment directory")

            with (experiment_dir / "summary.csv").open(
                newline="", encoding="utf-8-sig"
            ) as source:
                summaries = list(csv.DictReader(source))

            if len(summaries) != 1:
                raise RuntimeError(f"{name}: invalid summary")

            summary = summaries[0]

            if (
                summary["test_passed"] != "True"
                or summary["crypto_mode"] != mode
                or int(summary["test_mode"]) != 0
                or int(summary["accepted_unique_packets"]) != 80
            ):
                raise RuntimeError(f"{name}: unexpected experiment result")

            # Ensure the DLL remains unchanged throughout this series.
            current_hash = hashlib.sha256(
                dll_path.read_bytes()
            ).hexdigest()

            if current_hash != dll_hash:
                raise RuntimeError("Crypto DLL changed during the series")

            record = {
                "repetition": repetition,
                "position": position,
                "crypto_mode": mode,
                "started_at": started_at,
                "experiment_dir": experiment_dir.relative_to(ROOT).as_posix(),
                "log_file": log_path.name,
                "dll_sha256": dll_hash,
            }

            manifest.append(record)

            # Persist progress after each successful experiment.
            with (output_dir / "manifest.csv").open(
                "w", newline="", encoding="utf-8"
            ) as destination:
                writer = csv.DictWriter(
                    destination,
                    fieldnames=list(record),
                )
                writer.writeheader()
                writer.writerows(manifest)

            print(
                f"  PASS | window mean="
                f"{float(summary['window_start_to_ready_mean_ms']):.4f} ms | "
                f"max="
                f"{float(summary['window_start_to_ready_max_ms']):.4f} ms",
                flush=True,
            )

    print(f"\nCompleted: {len(manifest)}/18 experiments")
    print(f"Series directory: {output_dir}")


if __name__ == "__main__":
    main()