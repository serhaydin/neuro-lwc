import csv
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


ROOT = Path(__file__).resolve().parent
BUILD_DIR = ROOT / "cmake-build-debug"


def main():
    run_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
        + "_"
        + uuid4().hex[:8]
    )

    output_dir = ROOT / "results" / f"test_suite_{run_id}"
    output_dir.mkdir(parents=True, exist_ok=False)

    # Use the same Python interpreter that starts this runner.
    tests = [
        (
            "c_ascon",
            [str(BUILD_DIR / "test_ascon.exe")],
        ),
        (
            "c_aes_gcm",
            [str(BUILD_DIR / "test_aes_gcm.exe")],
        ),
        (
            "python_crypto_bridge",
            [sys.executable, str(ROOT / "test_crypto_dll.py")],
        ),
    ]

    for crypto_mode in ("none", "ascon", "aes-gcm"):
        modes = range(4) if crypto_mode == "none" else range(8)

        for test_mode in modes:
            tests.append(
                (
                    f"stream_{crypto_mode}_mode{test_mode}",
                    [
                        sys.executable,
                        str(ROOT / "data_flow_simulation.py"),
                        "--crypto-mode",
                        crypto_mode,
                        "--test-mode",
                        str(test_mode),
                    ],
                )
            )

    results = []

    for index, (name, command) in enumerate(tests, start=1):
        print(
            f"[{index}/{len(tests)}] Running {name}...",
            flush=True,
        )

        log_path = output_dir / f"{name}.log"
        started_at = time.perf_counter()
        return_code = None
        error = ""

        with log_path.open("w", encoding="utf-8") as log_file:
            try:
                completed = subprocess.run(
                    command,
                    cwd=ROOT,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    timeout=60,
                    check=False,
                )

                return_code = completed.returncode
                status = "PASS" if return_code == 0 else "FAIL"

            except subprocess.TimeoutExpired:
                status = "TIMEOUT"
                error = "Test exceeded 60 seconds."
                log_file.write(f"\n{error}\n")

            except OSError as exc:
                status = "ERROR"
                error = str(exc)
                log_file.write(f"\n{error}\n")

        duration_s = time.perf_counter() - started_at

        results.append({
            "test": name,
            "status": status,
            "return_code": return_code,
            "duration_s": round(duration_s, 3),
            "log_file": log_path.name,
            "error": error,
        })

        print(f"    {status} ({duration_s:.2f} s)", flush=True)

    summary_path = output_dir / "suite_summary.csv"

    with summary_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as summary_file:
        writer = csv.DictWriter(
            summary_file,
            fieldnames=list(results[0]),
        )
        writer.writeheader()
        writer.writerows(results)

    passed = sum(row["status"] == "PASS" for row in results)
    unsuccessful = len(results) - passed

    print("\nTest suite completed.")
    print(f"Total: {len(results)}")
    print(f"Passed: {passed}")
    print(f"Unsuccessful: {unsuccessful}")
    print(f"Results: {output_dir}")

    return 0 if unsuccessful == 0 else 1


if __name__ == "__main__":
    sys.exit(main())