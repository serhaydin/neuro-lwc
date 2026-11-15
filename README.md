# neuro-lwc

An academic project for comparing Ascon-AEAD128 and AES-128-GCM
using real EEG data streamed over UDP.

The current implementation supports authenticated encryption,
Python/C integration, packet validation, and CSV experiment logging.
Performance benchmarking is planned; the current tests verify
functional correctness.

## Requirements

Current development environment:

- Windows x64
- Python 3.13
- CLion with MinGW, CMake, and Ninja

Python and the compiled DLL must use the same architecture.

Install Python dependencies from the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install numpy pyedflib
```

## EEG dataset

The simulation uses `chb01_01.edf` from the CHB-MIT Scalp EEG dataset.

Place the file at:

```text
data/raw/chb01_01.edf
```

Raw EEG files are excluded from Git and must be supplied separately.

The default configuration reads four channels at 256 Hz, with
16 samples per channel in each 62.5 ms window. Each window produces
a 128-byte EEG payload.

## Build

1. Open the repository root in CLion as a CMake project.
2. Select the MinGW toolchain and Debug profile.
3. Use `cmake-build-debug` as the build directory.
4. Build these targets:
   - `neuro_crypto`
   - `test_ascon`
   - `test_aes_gcm`

The Python bridge expects the shared library at:

```text
cmake-build-debug/neuro_crypto.dll
```

The library targets are built rather than run. The two test targets
are executable programs.

## Run tests

Run `test_ascon` and `test_aes_gcm` from CLion.

Each executable currently performs 28 checks covering selected
known-answer vectors, encryption/decryption, authentication failures,
invalid arguments, buffer capacity, and payload boundaries.

Run the Python bridge test:

```powershell
.\.venv\Scripts\python.exe test_crypto_dll.py
```

This performs six checks across both algorithms.

## Run the EEG simulation

Set the options in `data_flow_simulation.py`:

```python
CRYPTO_MODE = "ascon"
TEST_MODE = 0
```

Then run:

```powershell
.\.venv\Scripts\python.exe data_flow_simulation.py
```

### Cryptographic modes

| CRYPTO_MODE | Operation |
|---|---|
| `"none"` | Plaintext reference |
| `"ascon"` | Ascon-AEAD128 |
| `"aes-gcm"` | AES-128-GCM |

### Test modes

| TEST_MODE | Scenario |
|---|---|
| 0 | Normal transmission |
| 1 | Drop packet 10 |
| 2 | Send packet 30 after packet 31 |
| 3 | Send packet 20 twice |
| 4 | Modify packet 10's ciphertext |
| 5 | Modify packet 10's authentication tag |
| 6 | Modify packet 10's timestamp, authenticated as AAD |
| 7 | Modify packet 10's nonce |

Modes 4–7 require an encrypted mode.

With the default five-second duration, 80 packets are planned.
Modes 1 and 4–7 expect packet 10 to be absent from accepted EEG data.
An intentionally rejected packet is part of a successful test.

Check the final `Test passed: True` message.

## Packet format

The plaintext packet contains:

```text
sequence + timestamp + EEG payload
```

The encrypted packet contains:

```text
sequence + timestamp + nonce + ciphertext + authentication tag
```

The 12-byte sequence/timestamp header is authenticated as AAD.
It remains readable but modifications invalidate authentication.

| Mode | Key | Nonce | Tag | Total application packet |
|---|---:|---:|---:|---:|
| Plaintext | — | — | — | 140 bytes |
| Ascon-AEAD128 | 16 bytes | 16 bytes | 16 bytes | 172 bytes |
| AES-128-GCM | 16 bytes | 12 bytes | 16 bytes | 168 bytes |

Packet sizes assume the default 128-byte EEG payload and exclude
UDP/IP headers.

## Key and nonce handling

Each encrypted experiment generates a fresh random 16-byte key
and a random nonce prefix in the parent process.

Each packet nonce consists of the experiment prefix followed by
the four-byte sequence number. Sequence-number overflow is rejected.

Duplicate and reordered test packets reuse the already constructed
packet rather than encrypting again with the same nonce.

Both local endpoints receive the experiment settings from the parent
process. This is a simulation setup, not a network key-distribution
protocol.

The receiver validates encrypted packets before updating sequence
tracking or accepting EEG samples. Previously accepted sequence
numbers are tracked to reject duplicates during the experiment.

## Results

Each completed experiment writes a directory under `results/`
containing:

- `sender_packets.csv`
- `receiver_packets.csv`
- `summary.csv`

The summary includes the crypto mode, packet counts, content
comparison, rejection counters, latency statistics, and test result.

The current `transfer_ms` measurement runs from the sender's
pre-encryption timestamp to the receiver's socket-receive timestamp.
It includes sender-side encryption and bridge overhead, but excludes
receiver-side authentication/decryption.

It is not a measurement of encryption alone or full end-to-end
processing latency.

## Cryptographic implementations

- Ascon-AEAD128 reference implementation:
  `third_party/ascon/`
- Mbed TLS 3.6.7 AES-GCM:
  `third_party/mbedtls/`

The Mbed TLS configuration enables AES, GCM, the cipher interface,
and Windows platform support. Hardware acceleration options are
disabled for the initial software comparison.

Third-party license files are retained in their respective directories.

## Scope and limitations

- The current pipeline uses UDP loopback on one Windows computer.
- Functional tests do not establish performance on constrained hardware.
- Performance comparisons require controlled builds and repeated runs.
- Long-duration and load testing remain future work.