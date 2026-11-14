from pathlib import Path
import time

import numpy as np
import pyedflib


EDF_PATH = (
    Path(__file__).resolve().parent
    / "data"
    / "raw"
    / "chb01_01.edf"
)

CHANNEL_NAMES = ["FP1-F7", "F7-T7", "T7-P7", "P7-O1"]

SAMPLE_RATE = 256
SAMPLES_PER_WINDOW = 16
WINDOW_SECONDS = SAMPLES_PER_WINDOW / SAMPLE_RATE  # 62.5 ms
SIMULATION_SECONDS = 5
# İlk simülasyonda tüm 1 saatin tamamı çalışmasın diye 5 saniye seçildi
PAYLOAD_BYTES = len(CHANNEL_NAMES) * SAMPLES_PER_WINDOW * 2
# Her paketin byte olarak boyutunu belirliyoruz

# 4 satır x 16 sütunluk bir array oluşturuyoruz, her bir satır bir channel'ı her bir sütun da sampling windowda
#alınan sample
# Alıcıyı simüle eden fonksiyon bu
def receiver(payload: bytes) -> np.ndarray:
    """Deserialize the received payload into four EEG channels."""
    # Eğer aldığımız paket boyutu 128 değilse hata döndürecek
    if len(payload) != PAYLOAD_BYTES:
        raise ValueError(f"Unexpected payload size: {len(payload)}")

    # Buradaki reshape ile o 4x16'lık array oluşturuluyor
    # Frombuffer, byteları sayı dizisi olarak okumaya yarıyor
    return np.frombuffer(payload, dtype="<i2").reshape(len(CHANNEL_NAMES), SAMPLES_PER_WINDOW)


def main():
        received_windows = []

        stream_start = time.perf_counter()

        for sequence in range(packet_count):
            sample_start = sequence * SAMPLES_PER_WINDOW

            # Read raw digital samples instead of physical-unit values.
            window = np.stack([
                reader.readSignal(
                    index,
                    start=sample_start,
                    n=SAMPLES_PER_WINDOW,
                    digital=True,
                )
                for index in channel_indices
            ])

            if window.min() < -32768 or window.max() > 32767:
                raise ValueError("Samples do not fit in signed 16 bits")

            # Little-endian signed 16-bit, channel-major layout.
            payload = window.astype("<i2").tobytes(order="C")

            # Release the packet when its acquisition window is complete.
            deadline = (stream_start + (sequence + 1) * WINDOW_SECONDS)
            remaining = deadline - time.perf_counter()

            if remaining > 0:
                time.sleep(remaining)

            sent_at = time.perf_counter()

            # Ideal in-process channel: direct delivery to the receiver.
            reconstructed = receiver(payload)

            received_at = time.perf_counter()

            if not np.array_equal(window, reconstructed):
                raise RuntimeError(
                    f"Data mismatch in packet {sequence}"
                )

            original_windows.append(window.copy())
            received_windows.append(reconstructed.copy())

            scheduling_lateness_ms = (sent_at - deadline) * 1000
            delivery_ms = (received_at - sent_at) * 1000

            print(
                f"Packet {sequence:03d} | "
                f"{len(payload)} bytes | "
                f"schedule lateness: {scheduling_lateness_ms:.3f} ms | "
                f"delivery + decoding: {delivery_ms:.3f} ms | "
                f"MATCH"
            )

        original = np.concatenate(original_windows, axis=1)
        received = np.concatenate(received_windows, axis=1)

        print("\nSimulation completed.")
        print(f"Received shape: {received.shape}")
        print(f"Total payload bytes: {packet_count * PAYLOAD_BYTES}")
        print(
            f"All samples match: "
            f"{np.array_equal(original, received)}"
        )

    finally:
        reader.close()


if __name__ == "__main__":
    main()