import socket
import time
import struct

import numpy as np
import pyedflib


def run_sender(
    edf_path,
    channel_names,
    sample_rate,
    samples_per_window,
    sim_seconds,
    receiver_host,
    receiver_port,
):
    if sample_rate <= 0 or samples_per_window <= 0 or sim_seconds <= 0:
        raise ValueError("Sample rate, window size and duration must be positive")

    if not channel_names:
        raise ValueError("At least one channel must be selected")

    if len(set(channel_names)) != len(channel_names):
        raise ValueError("Selected channel names must be unique")

    window_seconds = samples_per_window / sample_rate
    payload_bytes = len(channel_names) * samples_per_window * 2

    if not edf_path.is_file():
        raise FileNotFoundError(f"EDF file not found: {edf_path}")

    reader = pyedflib.EdfReader(str(edf_path))

    try:
        labels = [
            label.strip()
            for label in reader.getSignalLabels()
        ]

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

        sample_counts = reader.getNSamples()

        available_samples = min(
            int(sample_counts[index])
            for index in channel_indices
        )

        packet_count = min(
            int(sim_seconds / window_seconds),
            available_samples // samples_per_window,
        )

        if packet_count == 0:
            raise ValueError(
                "No complete windows available for the requested duration"
            )

        print(f"\nSelected channels: {channel_names}")
        print(f"Window: {window_seconds * 1000} ms")
        print(f"Payload: {payload_bytes} bytes")
        print(f"Packets to send: {packet_count}")
        print(f"Destination: {receiver_host}:{receiver_port}\n")

        total_sent_bytes = 0

        # Open one UDP socket for the entire stream.
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        ) as sock:
            destination = (receiver_host, receiver_port)
            header_struct = struct.Struct("!Id")
            stream_start = time.perf_counter()

            for sequence in range(packet_count):
                sample_start = sequence * samples_per_window

                # Read raw digital samples from each selected channel.
                window = np.stack([
                    reader.readSignal(
                        index,
                        start=sample_start,
                        n=samples_per_window,
                        digital=True,
                    )
                    for index in channel_indices
                ])

                if window.shape != (
                    len(channel_names),
                    samples_per_window,
                ):
                    raise ValueError("Incomplete EEG window")

                if window.min() < -32768 or window.max() > 32767:
                    raise ValueError(
                        "Samples do not fit in signed 16 bits"
                    )

                # Serialize channel by channel as little-endian int16.
                payload = window.astype("<i2").tobytes(order="C")

                if len(payload) != payload_bytes:
                    raise ValueError("Unexpected payload size")

                # Wait until this simulated acquisition window is complete.
                deadline = (
                    stream_start
                    + (sequence + 1) * window_seconds
                )

                remaining = deadline - time.perf_counter()

                if remaining > 0:
                    time.sleep(remaining)

                sent_at = time.perf_counter()

                #SİLİNECEK test komutu
                if sequence == 10:
                    print("TEST: packet 010 intentionally dropped")
                    continue

                header = header_struct.pack(sequence, sent_at)
                packet = header + payload

                sent_bytes = sock.sendto(packet, destination)

                if sent_bytes != len(packet):
                    raise RuntimeError("Incomplete UDP send")

                total_sent_bytes += sent_bytes


                #SİLİNECEK test kodu
                if sequence == 20:
                    duplicate_bytes = sock.sendto(packet, destination)
                    total_sent_bytes += duplicate_bytes

                    print("TEST: packet 020 intentionally duplicated")

                scheduling_lateness_ms = (sent_at - deadline) * 1000

                print(
                    f"Sent packet {sequence:03d} | "
                    f"payload: {len(payload)} bytes | "
                    f"header: {len(header)} bytes | "
                    f"total: {sent_bytes} bytes | "
                    f"schedule lateness: {scheduling_lateness_ms:.3f} ms"
                )

        print("\nSender completed.")
        print(f"Packets sent: {packet_count}")
        print(f"Total application bytes sent: {total_sent_bytes}")

        return packet_count;

    finally:
        reader.close()