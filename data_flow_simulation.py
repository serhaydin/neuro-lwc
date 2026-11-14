from pathlib import Path

from sender import run_sender


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
    run_sender(
        edf_path=EDF_PATH,
        channel_names=CHANNEL_NAMES,
        sample_rate=SAMPLE_RATE,
        samples_per_window=SAMPLES_PER_WINDOW,
        sim_seconds=SIMULATION_SECONDS,
        receiver_host=RECEIVER_HOST,
        receiver_port=RECEIVER_PORT,
    )


if __name__ == "__main__":
    main()