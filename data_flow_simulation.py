from pathlib import Path

from sender import run_sender
from multiprocessing import Process, Event
from receiver import run_receiver


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
RECEIVER_PORT = 5000


def main():
    receiver_ready = Event()

    receiver_process = Process(
        target=run_receiver,
        kwargs={
            "receiver_host": RECEIVER_HOST,
            "receiver_port": RECEIVER_PORT,
            "channel_count": len(CHANNEL_NAMES),
            "samples_per_window": SAMPLES_PER_WINDOW,
            "idle_timeout": 10.0,
            "ready_event": receiver_ready,
        },
    )

    receiver_process.start()

    try:
        # Receiver, portu açtıktan sonra hazır olduğunu bildirir.
        if not receiver_ready.wait(timeout=10.0):
            raise RuntimeError("Receiver could not become ready")
        run_sender(
            edf_path=EDF_PATH,
            channel_names=CHANNEL_NAMES,
            sample_rate=SAMPLE_RATE,
            samples_per_window=SAMPLES_PER_WINDOW,
            sim_seconds=SIMULATION_SECONDS,
            receiver_host=RECEIVER_HOST,
            receiver_port=RECEIVER_PORT,
        )

        # Son paketten sonra receiver'ın timeout ile kapanmasını bekle.
        receiver_process.join(timeout=15.0)

        if receiver_process.is_alive():
            raise RuntimeError("Receiver did not stop in time")

        if receiver_process.exitcode != 0:
            raise RuntimeError("Receiver failed")

    finally:
        if receiver_process.is_alive():
            receiver_process.terminate()

        receiver_process.join()

if __name__ == "__main__":
    main()