import socket
import struct
import time

import numpy as np


def run_receiver(
    receiver_host,
    receiver_port,
    channel_count,
    samples_per_window,
    idle_timeout=10.0,
    ready_event=None,
):
    if channel_count <= 0 or samples_per_window <= 0:
        raise ValueError("Channel count and window size must be positive")

    if idle_timeout <= 0:
        raise ValueError("Timeout must be positive")

    payload_bytes = channel_count * samples_per_window * 2
    header_struct = struct.Struct("!Id")
    packet_bytes = header_struct.size + payload_bytes
    received_windows = []
    received_packets = 0
    rejected_packets = 0

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    ) as sock:
        # Listen on the same IP and UDP port used by the sender.
        sock.bind((receiver_host, receiver_port))

        # Stop waiting if no packet arrives for this many seconds.
        sock.settimeout(idle_timeout)

        print(
            f"Receiver listening on "
            f"{receiver_host}:{receiver_port}",
            flush=True,
        )

        # Used later when main starts receiver and sender together.
        if ready_event is not None:
            ready_event.set()

        while True:
            try:
                # Large buffer prevents oversized packets from being
                # truncated to the expected payload size.
                packet, sender_address = sock.recvfrom(65535)
                received_at = time.perf_counter()

            except socket.timeout:
                print(
                    f"\nNo packets received for "
                    f"{idle_timeout} seconds. Receiver stopping."
                )
                break

            if len(packet) != packet_bytes:
                rejected_packets += 1

                print(
                    f"Rejected packet from {sender_address}: "
                    f"expected {packet_bytes} bytes, "
                    f"got {len(packet)}"
                )
                continue

            # Reverse the sender's serialization:
            # little-endian int16, channel-major layout.

            header = packet[:header_struct.size]
            payload = packet[header_struct.size:]

            sequence, sent_at = header_struct.unpack(header)

            transfer_ms = (received_at - sent_at) * 1000

            window = np.frombuffer(
                payload,
                dtype="<i2",
            ).reshape(
                channel_count,
                samples_per_window,
            )

            received_windows.append(window.copy())

            print(
                f"Received packet {sequence:03d} | "
                f"payload: {len(payload)} bytes | "
                f"total: {len(packet)} bytes | "
                f"transfer: {transfer_ms:.3f} ms | "
                f"shape: {window.shape}"
            )
            received_packets += 1

    print("\nReceiver completed.")
    print(f"Accepted packets: {received_packets}")
    print(f"Rejected packets: {rejected_packets}")
    print(
        f"Total accepted payload bytes: "
        f"{received_packets * payload_bytes}"
    )

    if not received_windows:
        print("No EEG data received.")
        return np.empty((channel_count, 0), dtype="<i2")

    received = np.concatenate(received_windows, axis=1)

    print(f"Received EEG shape: {received.shape}")

    return received


# Allows receiver.py to be run directly for the first test.
if __name__ == "__main__":
    run_receiver(
        receiver_host="127.0.0.1",
        receiver_port=5000,
        channel_count=4,
        samples_per_window=16,
    )