import socket
import time
import struct

import numpy as np
import pyedflib
from crypto_bridge import CryptoBridge


def run_sender(
    edf_path,
    channel_names,
    sample_rate,
    samples_per_window,
    sim_seconds,
    receiver_host,
    receiver_port,
    test_mode,
        #0 --> Normal Run
        #1 --> Packet Loss Test
        #2 --> Packet Out of Order Test
        #3 --> Packet Duplication Test

    crypto_mode="none",
    session_key=None,
    nonce_prefix=None,
):
    if test_mode not in range(8):
        raise ValueError("test_mode must be between 0 and 7")

    if test_mode >= 4 and crypto_mode == "none":
        raise ValueError("Tampering tests require encryption")

    if sample_rate <= 0 or samples_per_window <= 0 or sim_seconds <= 0:
        raise ValueError("Sample rate, window size and duration must be positive")

    if not channel_names:
        raise ValueError("At least one channel must be selected")

    if len(set(channel_names)) != len(channel_names):
        raise ValueError("Selected channel names must be unique")


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

        minimum_packets = {
            0: 1,
            1: 11,
            2: 32,
            3: 21,
            4: 11,
            5: 11,
            6: 11,
            7: 11,
        }

        if packet_count < minimum_packets[test_mode]:
            raise ValueError(
                f"Test mode {test_mode} requires at least "
                f"{minimum_packets[test_mode]} packets"
            )

        if packet_count > 2**32:
            raise ValueError("Packet count exceeds the sequence number range")

        print(f"\nSelected channels: {channel_names}")
        print(f"Window: {window_seconds * 1000} ms")
        print(f"Payload: {payload_bytes} bytes")
        print(f"Packets to send: {packet_count}")
        print(f"Destination: {receiver_host}:{receiver_port}\n")

        total_sent_bytes = 0
        original_payloads = {}
        send_records = []


        # Open one UDP socket for the entire stream.
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        ) as sock:
            destination = (receiver_host, receiver_port)
            header_struct = struct.Struct("!Id")
            stream_start = time.perf_counter()

            #(packet reordering)
            if test_mode == 2:
                held_packet = None

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
                original_payloads[sequence] = payload

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

                #(packet_loss)
                if test_mode == 1:
                    if sequence == 10:
                        print("TEST: packet 010 intentionally dropped")
                        continue

                header = header_struct.pack(sequence, sent_at)

                if crypto is None:
                    packet = header + payload
                else:
                    nonce = (
                            nonce_prefix
                            + sequence.to_bytes(4, "big")
                    )

                    ciphertext = crypto.encrypt(
                        payload,
                        session_key,
                        nonce,
                        aad=header,
                    )

                    packet = header + nonce + ciphertext

                if len(packet) > 65507:
                    raise ValueError("Packet exceeds the IPv4 UDP payload limit")

                # Modify one packet after encryption.
                if test_mode in (4, 5, 6, 7) and sequence == 10:
                    modified_packet = bytearray(packet)

                    if test_mode == 4:
                        # First ciphertext byte, after header and nonce.
                        index = header_struct.size + crypto.nonce_bytes
                        description = "ciphertext"

                    elif test_mode == 5:
                        # Last authentication tag byte.
                        index = len(packet) - 1
                        description = "authentication tag"

                    elif test_mode == 6:
                        # Last timestamp byte; leave the sequence unchanged.
                        index = header_struct.size - 1
                        description = "timestamp (AAD)"

                    else:
                        # First nonce byte.
                        index = header_struct.size
                        description = "nonce"

                    modified_packet[index] ^= 0x01
                    packet = bytes(modified_packet)

                    print(
                        f"TEST: packet {sequence:03d} "
                        f"intentionally modified: {description}"
                    )

                #(packet_reordering)
                if test_mode == 2:
                    if sequence == 30:
                        held_packet = packet
                        print("TEST: packet 030 held back")
                        continue

                send_call_at = time.perf_counter()
                sent_bytes = sock.sendto(packet, destination)

                if sent_bytes != len(packet):
                    raise RuntimeError("Incomplete UDP send")

                total_sent_bytes += sent_bytes

                send_records.append({
                    "sequence": sequence,
                    "send_type": "normal",
                    "timestamp_at": sent_at,
                    "send_call_at": send_call_at,
                    "scheduled_at": deadline,
                    "schedule_lateness_ms": (send_call_at - deadline) * 1000,
                    "packet_bytes": sent_bytes,
                    "payload_bytes": len(payload),
                })

                #test kodu (reordering)
                # Send packet 030 after packet 031.
                if test_mode == 2:
                    if sequence == 31 and held_packet is not None:
                        held_sequence, held_timestamp = header_struct.unpack(
                            held_packet[:header_struct.size]
                        )

                        held_send_at = time.perf_counter()
                        held_bytes = sock.sendto(held_packet, destination)

                        if held_bytes != len(held_packet):
                            raise RuntimeError("Incomplete UDP send for held packet")

                        total_sent_bytes += held_bytes

                        held_deadline = (
                                stream_start + (held_sequence + 1) * window_seconds
                        )

                        send_records.append({
                            "sequence": held_sequence,
                            "send_type": "reordered",
                            "timestamp_at": held_timestamp,
                            "send_call_at": held_send_at,
                            "scheduled_at": held_deadline,
                            "schedule_lateness_ms": (
                                                            held_send_at - held_deadline
                                                    ) * 1000,
                            "packet_bytes": held_bytes,
                            "payload_bytes": payload_bytes,
                        })

                        held_packet = None

                        print("TEST: packet 030 sent after packet 031")
                #test kodu (packet duplication)
                if test_mode == 3:
                    if sequence == 20:
                        duplicate_send_at = time.perf_counter()
                        duplicate_bytes = sock.sendto(packet, destination)

                        if duplicate_bytes != len(packet):
                            raise RuntimeError("Incomplete UDP send for duplicate packet")

                        total_sent_bytes += duplicate_bytes

                        send_records.append({
                            "sequence": sequence,
                            "send_type": "duplicate",
                            "timestamp_at": sent_at,
                            "send_call_at": duplicate_send_at,
                            "scheduled_at": deadline,
                            "schedule_lateness_ms": None,
                            "packet_bytes": duplicate_bytes,
                            "payload_bytes": len(payload),
                        })

                        print("TEST: packet 020 intentionally duplicated")

                scheduling_lateness_ms = (send_call_at - deadline) * 1000

                print(
                    f"Sent packet {sequence:03d} | "
                    f"payload: {len(payload)} bytes | "
                    f"header: {len(header)} bytes | "
                    f"total: {sent_bytes} bytes | "
                    f"schedule lateness: {scheduling_lateness_ms:.3f} ms"
                )

        print("\nSender completed.")
        print(f"Planned packets: {packet_count}")
        print(f"Total application bytes sent: {total_sent_bytes}")
        print(f"Actual UDP sends: {len(send_records)}")

        return packet_count, original_payloads, send_records

    finally:
        reader.close()
