# neuro-lwc

An academic project for comparing Ascon-AEAD128 and AES-128-GCM
using real EEG data streamed over UDP.

The current implementation supports authenticated encryption,
Python/C integration, packet validation, and CSV experiment logging.
Functional validation, C-level latency/throughput benchmarks,
and host-build memory analysis are implemented. Benchmarks cover
both per-packet AES context setup and session-level context reuse.

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

### Automated functional suite

Build `test_ascon`, `test_aes_gcm`, and `neuro_crypto` in the Debug
profile, then run:

```powershell
.\.venv\Scripts\python.exe run_tests.py
```

The runner executes 23 test programs/scenarios:

- Two C test executables, each containing 28 checks.
- One Python DLL integration test containing six checks.
- Twenty streaming scenarios: modes 0-3 for plaintext and modes
  0-7 for each encrypted algorithm.

Individual logs and `suite_summary.csv` are saved under a unique
`results/test_suite_*` directory. Any unsuccessful test produces
a nonzero suite exit code.

## Run the EEG simulation

Select the crypto mode and test scenario through CLI arguments:

```powershell
.\.venv\Scripts\python.exe data_flow_simulation.py --crypto-mode ascon --test-mode 0
```

Without arguments, the script uses the `CRYPTO_MODE` and `TEST_MODE`
defaults defined in `data_flow_simulation.py`.

Alternatively, run with the defaults:

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

## C-level performance benchmarks

Create a Release CMake profile using the same MinGW toolchain and
`cmake-build-release` as the build directory.

Build:

- `benchmark_crypto`
- `benchmark_crypto_session`

The recorded environment uses an AMD Ryzen 7 7840HS, Windows 11 x64,
GCC 15.2.0, and Release flags `-O3 -DNDEBUG`.
AES hardware acceleration is disabled in `mbedtls_config.h`.

### Benchmark modes

| Target | AES context handling | Timed work |
|---|---|---|
| `benchmark_crypto` | Created and freed for each operation | Wrapper validation, allocation, key setup, packet cryptography, and cleanup |
| `benchmark_crypto_session` | Separate encryption/decryption contexts prepared once and reused | Adapter validation and packet cryptography; context setup and cleanup excluded |

Ascon uses the existing one-shot C wrapper in both modes.
The session target is a benchmark implementation; the EEG streaming
pipeline still uses the original wrappers.

Each benchmark uses:

- 128-byte synthetic payloads and 12-byte AAD.
- 16-byte authentication tags.
- Algorithm-specific nonce lengths and unique nonces per encryption
  within a program run.
- One warm-up batch of 1,000 packets per algorithm.
- Thirty measured rounds of 1,000 packets per algorithm.
- Alternating algorithm order between rounds.
- Windows `QueryPerformanceCounter` for timing.

Encryption and authenticated decryption are timed separately.
Nonce preparation, payload comparisons, modified-tag rejection
checks, and console output occur outside timed sections.

Each timing includes loop, function-call, and result-storage overhead.
It is a measurement of the selected implementation path rather than
an isolated cryptographic instruction cost.

### Run and analyze

```powershell
.\cmake-build-release\benchmark_crypto.exe
.\cmake-build-release\benchmark_crypto_session.exe
```

Save stdout as a UTF-8 CSV, then analyze it:

```powershell
.\.venv\Scripts\python.exe analyze_benchmark.py "PATH_TO_RAW_CSV"
```

Every raw CSV contains 60 rows: 30 per algorithm.
Latency values are batch averages in microseconds per packet.
Throughput uses plaintext payload bytes and is expressed in MiB/s.

`analyze_benchmark.py` reports statistics across the 30 batch averages.
These statistics do not describe the distribution of individual
packet latencies.

### Repeated and paired experiments

`summarize_repeats.py` analyzes five separate runs stored as
`run_1.csv` through `run_5.csv` in one directory:

```powershell
.\.venv\Scripts\python.exe summarize_repeats.py "RESULTS_DIRECTORY"
```

Across-run standard deviations are calculated from the five run
means. The 150 rounds are not treated as 150 independent experiments.

Paired experiments contain six pairs of per-packet and session
runs. The mode order alternates between pairs.

```powershell
.\.venv\Scripts\python.exe analyze_paired.py "PAIRED_RESULTS_DIRECTORY"
```

The paired analyzer validates `manifest.csv`, recorded executable
hash consistency, run order, and raw measurements. It writes
`paired_comparisons.csv` and `paired_aggregate.csv`.

Observed reductions include possible system-condition differences.
Changes in the unchanged Ascon path provide an indication of this
variation; they are not used as an exact correction factor.
Paired percentage reductions are calculated within each pair and
then averaged.

## Host-build memory analysis

Build these targets in the Release profile:

- `footprint_ascon`
- `footprint_aes_gcm`
- `inspect_crypto_memory`

The footprint targets use the same 128-byte round-trip validation
program, linked separately to each algorithm.

### Executable sections

Recorded GNU `size` results:

| Target | text (B) | data (B) | bss (B) |
|---|---:|---:|---:|
| `footprint_ascon` | 37452 | 224 | 320 |
| `footprint_aes_gcm` | 30444 | 224 | 9184 |

These totals include linked library components and Windows runtime
support. They are host executable section sizes, not isolated
algorithm sizes or microcontroller Flash/RAM measurements.

AES lookup tables account for 8,768 bytes of the observed BSS.
The result depends on the selected Mbed TLS configuration.

### Stack reports

Create a separate Release profile with:

- Build directory: `cmake-build-stack`
- CMake option: `-DCMAKE_C_FLAGS=-fstack-usage`

Build both footprint targets and inspect the generated `.su` files.

Recorded wrapper stack requirements:

| Function | Reported stack (B) |
|---|---:|
| `ascon_aead_encrypt` | 144 |
| `ascon_aead_decrypt` | 128 |
| `aes_gcm_encrypt` | 608 |
| `aes_gcm_decrypt` | 576 |

These are per-function compiler reports. They do not establish peak
stack usage across nested calls. Application buffers, library call
paths, and first-use initialization must be considered separately.

### Heap and context sizes

In the current Mbed TLS configuration, each original AES-GCM wrapper
call allocates an AES context and frees it before returning.

`inspect_crypto_memory` reports:

| Structure | Size (B) |
|---|---:|
| `mbedtls_aes_context` | 288 |
| `mbedtls_cipher_context_t` | 96 |
| `mbedtls_gcm_context` | 424 |

The 288-byte allocation excludes allocator overhead.
The cipher context is embedded in the GCM context; these sizes must
not be added together. The local GCM context is already included in
the wrapper's reported stack frame.

The session benchmark retains two AES contexts, one per direction,
until cleanup. The selected Ascon C path performs no heap allocation.

## Scope and limitations

- Streaming uses UDP loopback on one Windows computer.
- Host benchmark results do not establish performance on constrained
  hardware.
- Comparisons depend on implementation, build configuration, context
  lifecycle, and system conditions.
- Executable sections, per-function stack reports, and requested heap
  allocations are separate measurements; peak total RAM usage has
  not been established.
- The current streaming `transfer_ms` excludes receiver-side
  authentication/decryption.
- Session keys are supplied by the parent process. Authenticated
  ECDH/KDF session establishment remains future work.
- Energy consumption, long-duration behavior, and load performance
  have not been measured.