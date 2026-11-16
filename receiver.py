import socket
import struct
import time

from crypto_bridge import CryptoBridge, AuthenticationError
import numpy as np


def run_receiver(
    receiver_host,
    receiver_port,
    channel_count,
    samples_per_window,
    idle_timeout=2.0,
    ready_event=None,
    expected_packets=None,
    result_queue=None,
    crypto_mode="none",
    session_key=None,
    nonce_prefix=None,
):
    if channel_count <= 0 or samples_per_window <= 0:
        raise ValueError("Channel count and window size must be positive")

    if idle_timeout <= 0:
        raise ValueError("Timeout must be positive")

    if crypto_mode not in ("none", "ascon", "aes-gcm"):
        raise ValueError("Unsupported crypto mode")

    crypto = None

    if crypto_mode != "none":
        crypto = CryptoBridge(crypto_mode)

        if not isinstance(session_key, bytes) or len(session_key) != 16:
            raise ValueError("Session key must be 16 bytes")

        expected_prefix_bytes = crypto.nonce_bytes - 4

        if (
            not isinstance(nonce_prefix, bytes)
            or len(nonce_prefix) != expected_prefix_bytes
        ):
            raise ValueError("Invalid nonce prefix")

    payload_bytes = channel_count * samples_per_window * 2
    header_struct = struct.Struct("!Id")
    packet_bytes = header_struct.size + payload_bytes
    if crypto is not None:
        packet_bytes += crypto.nonce_bytes + crypto.TAG_BYTES
    received_windows = []
    receive_records = []
    received_packets = 0
    rejected_packets = 0
    seen_sequences = set()
    highest_sequence = -1
    duplicate_packets = 0
    out_of_order_packets = 0
    rejected_auth_packets = 0
    rejected_nonce_packets = 0

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

                receive_records.append({
                    "sequence": None,
                    "status": "invalid_size",
                    "timestamp_at": None,
                    "received_at": received_at,
                    "transfer_ms": None,
                    "packet_bytes": len(packet),
                })

                print(
                    f"Rejected packet from {sender_address}: "
                    f"expected {packet_bytes} bytes, "
                    f"got {len(packet)}"
                )
                continue

            # Reverse the sender's serialization:
            # little-endian int16, channel-major layout.

            header = packet[:header_struct.size]
            sequence, sent_at = header_struct.unpack(header)

            if crypto is None:
                payload = packet[header_struct.size:]
            else:
                nonce_end = header_struct.size + crypto.nonce_bytes
                nonce = packet[header_struct.size:nonce_end]
                ciphertext = packet[nonce_end:]

                expected_nonce = (
                        nonce_prefix
                        + sequence.to_bytes(4, "big")
                )

                if nonce != expected_nonce:
                    rejected_nonce_packets += 1

                    receive_records.append({
                        "sequence": None,
                        "status": "invalid_nonce",
                        "timestamp_at": None,
                        "received_at": received_at,
                        "transfer_ms": None,
                        "packet_bytes": len(packet),
                    })

                    print("Rejected packet: unexpected nonce")
                    continue

                try:
                    payload = crypto.decrypt(
                        ciphertext,
                        session_key,
                        nonce,
                        aad=header,
                    )
                except AuthenticationError:
                    rejected_auth_packets += 1

                    receive_records.append({
                        "sequence": None,
                        "status": "auth_failed",
                        "timestamp_at": None,
                        "received_at": received_at,
                        "transfer_ms": None,
                        "packet_bytes": len(packet),
                    })

                    print("Rejected packet: authentication failed")
                    continue

            transfer_ms = (received_at - sent_at) * 1000

            if sequence in seen_sequences:
                duplicate_packets += 1

                receive_records.append({
                    "sequence": sequence,
                    "status": "duplicate",
                    "timestamp_at": sent_at,
                    "received_at": received_at,
                    "transfer_ms": transfer_ms,
                    "packet_bytes": len(packet),
                })

                print(f"Duplicate packet {sequence:03d}: ignored")
                continue

            out_of_order = sequence < highest_sequence

            if out_of_order:
                out_of_order_packets += 1

            seen_sequences.add(sequence)
            highest_sequence = max(highest_sequence, sequence)

            window = np.frombuffer(
                payload,
                dtype="<i2",
            ).reshape(
                channel_count,
                samples_per_window,
            )

            received_windows.append((sequence, window.copy()))

            # This packet's validated EEG window is now available.
            ready_at = time.perf_counter()

            receiver_processing_ms = (
                ready_at - received_at
            ) * 1000

            packet_ready_ms = (
                ready_at - sent_at
            ) * 1000

            receive_records.append({
                "sequence": sequence,
                "status": "out_of_order" if out_of_order else "accepted",
                "timestamp_at": sent_at,
                "received_at": received_at,
                "transfer_ms": transfer_ms,
                "packet_bytes": len(packet),
                "ready_at": ready_at,
                "receiver_processing_ms": receiver_processing_ms,
                "packet_ready_ms": packet_ready_ms,
            })

            if out_of_order:
                print(f"Out-of-order packet {sequence:03d}")

            print(
                f"Received packet {sequence:03d} | "
                f"payload: {len(payload)} bytes | "
                f"total: {len(packet)} bytes | "
                f"transfer: {transfer_ms:.3f} ms | "
                f"shape: {window.shape}"
            )
            received_packets += 1

    if result_queue is not None:
        result_queue.put({
            "windows": list(received_windows),
            "records": receive_records,
            "stats": {
                "accepted_unique_packets": received_packets,
                "rejected_size_packets": rejected_packets,
                "duplicate_packets": duplicate_packets,
                "out_of_order_packets": out_of_order_packets,
                "rejected_auth_packets": rejected_auth_packets,
                "rejected_nonce_packets": rejected_nonce_packets,
            },
        })

    print("\nReceiver completed.")
    print(f"Accepted unique packets: {received_packets}")
    print(f"Rejected size-invalid packets: {rejected_packets}")
    print(f"Duplicate packets: {duplicate_packets}")
    print(f"Out-of-order unique packets: {out_of_order_packets}")
    print(f"Authentication failures: {rejected_auth_packets}")
    print(f"Unexpected nonces: {rejected_nonce_packets}")
    print(
        f"Total accepted payload bytes: "
        f"{received_packets * payload_bytes}"
    )

    expected_count = (
        expected_packets.value
        if expected_packets is not None
        else -1
    )

    if expected_count >= 0:
        expected_sequences = set(range(expected_count))

        missing_sequences = sorted(
            expected_sequences - seen_sequences
        )

        unexpected_sequences = sorted(
            seen_sequences - expected_sequences
        )

        print(f"Expected packets: {expected_count}")
        print(f"Missing packets: {len(missing_sequences)}")
        print(f"Missing sequence numbers: {missing_sequences}")
        print(f"Unexpected sequence numbers: {unexpected_sequences}")

    else:
        print("Expected packet count unknown; loss cannot be calculated.")

    if not received_windows:
        print("No EEG data received.")
        return np.empty((channel_count, 0), dtype="<i2")

    # Restore sequence order before combining the windows.
    received_windows.sort(key=lambda item: item[0])

    received = np.concatenate(
        [window for sequence, window in received_windows],
        axis=1,
    )

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