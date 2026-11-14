import time

import numpy as np
import pyedflib

def run_sender(edf_path, channel_names, sample_rate, samples_per_window, simu_seconds):

    window_seconds = samples_per_window / sample_rate
    payload_bytes = len(channel_names) * samples_per_window * 2

    if not edf_path.is_file():
        raise FileNotFoundError(f"EDF file not found: {edf_path}")

    reader = pyedflib.EdfReader(str(edf_path))

    try:
        labels = [label.strip() for label in reader.getSignalLabels()]

        print(f"File: {edf_path.name}")
        print(f"Recording duration: {reader.getFileDuration()} seconds")
        print(f"Available channels: {labels}")

        channel_indices = []

        for name in channel_names:
            matches = [
                index
                for index, label in enumerate(labels)
                if label == name
            ]

            if len(matches) != 1:
                raise ValueError(
                    f"Channel must exist exactly once: {name}"
                )

            index = matches[0]
            frequency = reader.getSampleFrequency(index)

            if frequency != sample_rate:
                raise ValueError(
                    f"{name}: expected {sample_rate} Hz, got {frequency}"
                )

            channel_indices.append(index)

        available_samples = min(
            int(reader.getNSamples()[index])
            for index in channel_indices
        )

        packet_count = min(
            int(simu_seconds / window_seconds),
            available_samples // samples_per_window,
        )

        if packet_count == 0:
            raise ValueError("Recording has no complete windows")

        print(f"\nSelected channels: {channel_names}")
        print(f"Window: {window_seconds * 1000} ms")
        print(f"Payload: {payload_bytes} bytes")
        print(f"Packets to send: {packet_count}\n")

        original_windows = []

        stream_start = time.perf_counter()

        for sequence in range(packet_count):
            sample_start = sequence * samples_per_window

            # Read raw digital samples instead of physical-unit values.
            window = np.stack([
                reader.readSignal(
                    index,
                    start=sample_start,
                    n=samples_per_window,
                    digital=True,
                )
                for index in channel_indices
            ])

            if window.min() < -32768 or window.max() > 32767:
                raise ValueError("Samples do not fit in signed 16 bits")

            # Little-endian signed 16-bit, channel-major layout.
            payload = window.astype("<i2").tobytes(order="C")

            # Release the packet when its acquisition window is complete.
            deadline = (stream_start + (sequence + 1) * window_seconds)
            remaining = deadline - time.perf_counter()

            if remaining > 0:
                time.sleep(remaining)

            sent_at = time.perf_counter()
    finally:
        reader.close()