import ctypes
from pathlib import Path


DLL_PATH = (
    Path(__file__).resolve().parent
    / "cmake-build-debug"
    / "neuro_crypto.dll"
)

Byte = ctypes.c_uint8
BytePointer = ctypes.POINTER(Byte)
Size = ctypes.c_size_t

OK = 0
AUTH_FAILED = -3


def to_buffer(data):
    # Keep a valid address even for empty input.
    return (Byte * max(1, len(data))).from_buffer_copy(
        data if data else b"\x00"
    )


def configure_function(function):
    function.argtypes = [
        BytePointer,                 # Output buffer
        Size,                        # Output capacity
        ctypes.POINTER(Size),        # Output length
        BytePointer,                 # Input buffer
        Size,                        # Input length
        BytePointer,                 # AAD
        Size,                        # AAD length
        BytePointer,                 # Key
        BytePointer,                 # Nonce
    ]
    function.restype = ctypes.c_int
    return function


def check(condition, description):
    if not condition:
        raise RuntimeError(f"[FAIL] {description}")

    print(f"[PASS] {description}")


def test_algorithm(library, name, prefix, nonce_size):
    encrypt = configure_function(
        getattr(library, f"{prefix}_encrypt")
    )
    decrypt = configure_function(
        getattr(library, f"{prefix}_decrypt")
    )

    # Fixed values are for this isolated test only.
    key = to_buffer(bytes(range(16)))
    nonce = to_buffer(bytes(range(nonce_size)))
    aad_data = b"EEG packet header"
    aad = to_buffer(aad_data)

    payload = bytes(range(128))
    plaintext = to_buffer(payload)

    ciphertext = (Byte * (len(payload) + 16))()
    ciphertext_len = Size(0)

    status = encrypt(
        ciphertext,
        len(ciphertext),
        ctypes.byref(ciphertext_len),
        plaintext,
        len(payload),
        aad,
        len(aad_data),
        key,
        nonce,
    )

    check(
        status == OK and ciphertext_len.value == len(payload) + 16,
        f"{name}: encrypt 128 bytes through DLL",
    )

    recovered = (Byte * len(payload))()
    recovered_len = Size(0)

    status = decrypt(
        recovered,
        len(recovered),
        ctypes.byref(recovered_len),
        ciphertext,
        ciphertext_len.value,
        aad,
        len(aad_data),
        key,
        nonce,
    )

    check(
        status == OK
        and recovered_len.value == len(payload)
        and bytes(recovered) == payload,
        f"{name}: decrypt and recover original data",
    )

    # Modify the ciphertext and verify rejection.
    ciphertext[0] ^= 0x01

    ctypes.memset(recovered, 0xAA, len(recovered))
    recovered_len.value = 999

    status = decrypt(
        recovered,
        len(recovered),
        ctypes.byref(recovered_len),
        ciphertext,
        ciphertext_len.value,
        aad,
        len(aad_data),
        key,
        nonce,
    )

    check(
        status == AUTH_FAILED
        and recovered_len.value == 0
        and bytes(recovered) == bytes(len(payload)),
        f"{name}: reject tampering and clear plaintext",
    )


def main():
    if not DLL_PATH.is_file():
        raise FileNotFoundError(f"DLL not found: {DLL_PATH}")

    # CDLL matches the C calling convention used by our functions.
    library = ctypes.CDLL(str(DLL_PATH))

    print(f"Loaded: {DLL_PATH}\n")

    test_algorithm(library, "Ascon-AEAD128", "ascon_aead", 16)
    test_algorithm(library, "AES-128-GCM", "aes_gcm", 12)

    print("\nAll 6 DLL integration checks passed.")


if __name__ == "__main__":
    main()