from pathlib import Path

from sender import run_sender
from multiprocessing import Process, Event, Value, Queue
from queue import Empty
from receiver import run_receiver

import numpy as np
import csv
import secrets
from datetime import datetime, timezone
from uuid import uuid4

EDF_PATH = (
    Path(__file__).resolve().parent
    / "data"
    / "raw"
    / "chb01_01.edf"
)

CHANNEL_NAMES = ["FP1-F7", "F7-T7", "T7-P7", "P7-O1"]

SAMPLE_RATE = 256
SAMPLES_PER_WINDOW = 16
SIMULATION_SECONDS = 5

RECEIVER_HOST = "127.0.0.1"
RECEIVER_PORT = 65535

# Test modes:
# 0: Normal transmission.
# 1: Drop packet 10 to test packet loss detection.
# 2: Send packet 30 after packet 31 to test out-of-order detection.
# 3: Send packet 20 twice to test duplicate detection.
# 4: Modify packet 10's ciphertext to test authentication failure.
# 5: Modify packet 10's tag to test authentication failure.
# 6: Modify packet 10's timestamp (AAD) to test header authentication.
# 7: Modify packet 10's nonce to test nonce validation.
# Modes 4-7 require encryption; the modified packet must be rejected.
TEST_MODE = 0
CRYPTO_MODE = "ascon"  # "none", "ascon", "aes-gcm"

NONCE_BYTES = {
    "ascon": 16,
    "aes-gcm": 12,
}

SEQUENCE_BYTES = 4

def write_csv(file_path, rows, fieldnames):
    with file_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)

def main():

    if CRYPTO_MODE not in ("none", "ascon", "aes-gcm"):
        raise ValueError("CRYPTO_MODE must be none, ascon or aes-gcm")

    # Generate once in the parent process and share with both endpoints.
    session_key = None
    nonce_prefix = None

    if CRYPTO_MODE != "none":
        session_key = secrets.token_bytes(16)

        prefix_bytes = NONCE_BYTES[CRYPTO_MODE] - SEQUENCE_BYTES
        nonce_prefix = secrets.token_bytes(prefix_bytes)

    print(f"Crypto mode: {CRYPTO_MODE}")

    result_queue = Queue()
    receiver_ready = Event()
    expected_packets = Value("q", -1)

    receiver_process = Process(
        target=run_receiver,
        kwargs={
            "receiver_host": RECEIVER_HOST,
            "receiver_port": RECEIVER_PORT,
            "channel_count": len(CHANNEL_NAMES),
            "samples_per_window": SAMPLES_PER_WINDOW,
            "idle_timeout":2.0,
            "ready_event": receiver_ready,
            "expected_packets": expected_packets,
            "result_queue": result_queue,
            "crypto_mode": CRYPTO_MODE,
            "session_key": session_key,
            "nonce_prefix": nonce_prefix,
        },
    )

    receiver_process.start()

    try:
        # Receiver, portu açtıktan sonra hazır olduğunu bildirir.
        if not receiver_ready.wait(timeout=10.0):
            raise RuntimeError("Receiver could not become ready")
        packet_count, original_payloads, send_records = run_sender(
            edf_path=EDF_PATH,
            channel_names=CHANNEL_NAMES,
            sample_rate=SAMPLE_RATE,
            samples_per_window=SAMPLES_PER_WINDOW,
            sim_seconds=SIMULATION_SECONDS,
            receiver_host=RECEIVER_HOST,
            receiver_port=RECEIVER_PORT,
            test_mode=TEST_MODE,
            crypto_mode=CRYPTO_MODE,
            session_key=session_key,
            nonce_prefix=nonce_prefix,
        )

        expected_packets.value = packet_count

        try:
            receiver_result = result_queue.get(timeout=15.0)
        except Empty as exc:
            raise RuntimeError("Receiver did not provide results") from exc

        received_windows = receiver_result["windows"]
        receive_records = receiver_result["records"]
        receiver_stats = receiver_result["stats"]

        # Son paketten sonra receiver'ın timeout ile kapanmasını bekle.
        receiver_process.join(timeout=15.0)

        if receiver_process.is_alive():
            raise RuntimeError("Receiver did not stop in time")

        if receiver_process.exitcode != 0:
            raise RuntimeError("Receiver failed")

        matched_packets = 0
        mismatched_sequences = []
        unexpected_sequences = []
        received_sequences = set()

        for sequence, window in received_windows:
            received_sequences.add(sequence)

            if sequence not in original_payloads:
                unexpected_sequences.append(sequence)
                continue

            expected_window = np.frombuffer(
                original_payloads[sequence],
                dtype="<i2",
            ).reshape(
                len(CHANNEL_NAMES),
                SAMPLES_PER_WINDOW,
            )

            if np.array_equal(expected_window, window):
                matched_packets += 1
            else:
                mismatched_sequences.append(sequence)

        missing_sequences = sorted(
            set(original_payloads) - received_sequences
        )

        print("\nContent comparison completed.")
        print(f"Matching packets: {matched_packets}")
        print(f"Mismatched sequences: {mismatched_sequences}")
        print(f"Missing sequences: {missing_sequences}")
        print(f"Unexpected sequences: {unexpected_sequences}")

        expected_missing = (
            [10] if TEST_MODE in (1, 4, 5, 6, 7) else []
        )
        expected_duplicates = 1 if TEST_MODE == 3 else 0
        expected_out_of_order = 1 if TEST_MODE == 2 else 0
        expected_auth_failures = 1 if TEST_MODE in (4, 5, 6) else 0
        expected_nonce_failures = 1 if TEST_MODE == 7 else 0

        expected_unique = packet_count - len(expected_missing)

        # Loss mode skips a send; duplication mode adds a send.
        expected_sends = (
                packet_count
                - (1 if TEST_MODE == 1 else 0)
                + expected_duplicates
        )

        test_passed = (
                not mismatched_sequences
                and not unexpected_sequences
                and missing_sequences == expected_missing
                and matched_packets == expected_unique
                and receiver_stats["accepted_unique_packets"] == expected_unique
                and len(send_records) == expected_sends
                and len(receive_records) == expected_sends
                and receiver_stats["duplicate_packets"] == expected_duplicates
                and receiver_stats["out_of_order_packets"] == expected_out_of_order
                and receiver_stats["rejected_size_packets"] == 0
                and receiver_stats["rejected_auth_packets"]
                == expected_auth_failures
                and receiver_stats["rejected_nonce_packets"]
                == expected_nonce_failures
        )

        # Use only accepted unique packets for latency statistics.
        transfer_times = [
            record["transfer_ms"]
            for record in receive_records
            if record["status"] in ("accepted", "out_of_order")
        ]

        run_id = (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
            + "_"
            + uuid4().hex[:8]
        )

        output_dir = (
            Path(__file__).resolve().parent
            / "results"
            / f"{run_id}_mode{TEST_MODE}"
        )

        output_dir.mkdir(parents=True, exist_ok=False)

        write_csv(
            output_dir / "sender_packets.csv",
            send_records,
            [
                "sequence",
                "send_type",
                "timestamp_at",
                "send_call_at",
                "scheduled_at",
                "schedule_lateness_ms",
                "packet_bytes",
                "payload_bytes",
            ],
        )

        write_csv(
            output_dir / "receiver_packets.csv",
            receive_records,
            [
                "sequence",
                "status",
                "timestamp_at",
                "received_at",
                "transfer_ms",
                "packet_bytes",
            ],
        )

        summary = {
            "run_id": run_id,
            "test_mode": TEST_MODE,
            "edf_file": EDF_PATH.name,
            "channels": ";".join(CHANNEL_NAMES),
            "sample_rate_hz": SAMPLE_RATE,
            "samples_per_window": SAMPLES_PER_WINDOW,
            "window_ms": SAMPLES_PER_WINDOW / SAMPLE_RATE * 1000,
            "requested_duration_s": SIMULATION_SECONDS,
            "receiver_host": RECEIVER_HOST,
            "receiver_port": RECEIVER_PORT,
            "planned_packets": packet_count,
            "actual_udp_sends": len(send_records),
            "received_datagrams": len(receive_records),
            "accepted_unique_packets": receiver_stats[
                "accepted_unique_packets"
            ],
            "duplicate_packets": receiver_stats["duplicate_packets"],
            "out_of_order_packets": receiver_stats[
                "out_of_order_packets"
            ],
            "rejected_size_packets": receiver_stats[
                "rejected_size_packets"
            ],
            "missing_packets": len(missing_sequences),
            "missing_sequences": ";".join(map(str, missing_sequences)),
            "matching_packets": matched_packets,
            "mismatched_sequences": ";".join(
                map(str, mismatched_sequences)
            ),
            "unexpected_sequences": ";".join(
                map(str, unexpected_sequences)
            ),
            "application_bytes_sent": sum(
                record["packet_bytes"] for record in send_records
            ),
            "transfer_mean_ms": (
                float(np.mean(transfer_times)) if transfer_times else None
            ),
            "transfer_max_ms": (
                float(np.max(transfer_times)) if transfer_times else None
            ),
            "transfer_p95_ms": (
                float(np.percentile(transfer_times, 95))
                if transfer_times else None
            ),
            "test_passed": test_passed,
            "crypto_mode": CRYPTO_MODE,
            "rejected_auth_packets": receiver_stats["rejected_auth_packets"],
            "rejected_nonce_packets": receiver_stats["rejected_nonce_packets"],
        }

        write_csv(
            output_dir / "summary.csv",
            [summary],
            list(summary),
        )

        print(f"\nResults saved to: {output_dir}")
        print(f"Test passed: {test_passed}")

        if not test_passed:
            raise RuntimeError(
                "Experiment validation failed; inspect saved CSV files"
            )

    finally:
        if receiver_process.is_alive():
            receiver_process.terminate()

        receiver_process.join()

        result_queue.close()
        result_queue.join_thread()

if __name__ == "__main__":
    main()