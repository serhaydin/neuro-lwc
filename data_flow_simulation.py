from pathlib import Path

from sender import run_sender
from multiprocessing import Process, Event, Value, Queue
from queue import Empty
from receiver import run_receiver

import numpy as np

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

TEST_MODE = 0

def main():
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
            "idle_timeout": 10.0,
            "ready_event": receiver_ready,
            "expected_packets": expected_packets,
            "result_queue": result_queue,
        },
    )

    receiver_process.start()

    try:
        # Receiver, portu açtıktan sonra hazır olduğunu bildirir.
        if not receiver_ready.wait(timeout=10.0):
            raise RuntimeError("Receiver could not become ready")
        packet_count, original_payloads = run_sender(
            edf_path=EDF_PATH,
            channel_names=CHANNEL_NAMES,
            sample_rate=SAMPLE_RATE,
            samples_per_window=SAMPLES_PER_WINDOW,
            sim_seconds=SIMULATION_SECONDS,
            receiver_host=RECEIVER_HOST,
            receiver_port=RECEIVER_PORT,
            test_mode=TEST_MODE,
        )

        expected_packets.value = packet_count

        try:
            received_windows = result_queue.get(timeout=15.0)
        except Empty as exc:
            raise RuntimeError("Receiver did not provide results") from exc

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

        expected_missing = [10] if TEST_MODE == 1 else []

        if mismatched_sequences or unexpected_sequences:
            raise RuntimeError("EEG content validation failed")

        if missing_sequences != expected_missing:
            raise RuntimeError(
                f"Unexpected missing packets: "
                f"expected {expected_missing}, got {missing_sequences}"
            )

    finally:
        if receiver_process.is_alive():
            receiver_process.terminate()

        receiver_process.join()

        result_queue.close()
        result_queue.join_thread()

if __name__ == "__main__":
    main()