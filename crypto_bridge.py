import ctypes
from pathlib import Path


class AuthenticationError(Exception):
    """The ciphertext, tag, AAD, key or nonce failed authentication."""


class CryptoBridge:
    KEY_BYTES = 16
    TAG_BYTES = 16

    ALGORITHMS = {
        "ascon": ("ascon_aead", 16),
        "aes-gcm": ("aes_gcm", 12),
    }

    def __init__(self, algorithm, dll_path=None):
        if algorithm not in self.ALGORITHMS:
            raise ValueError(
                f"Unsupported algorithm: {algorithm}. "
                f"Choose from: {tuple(self.ALGORITHMS)}"
            )

        self.algorithm = algorithm
        prefix, self.nonce_bytes = self.ALGORITHMS[algorithm]

        if dll_path is None:
            dll_path = (
                Path(__file__).resolve().parent
                / "cmake-build-debug"
                / "neuro_crypto.dll"
            )

        self.dll_path = Path(dll_path).resolve()

        if not self.dll_path.is_file():
            raise FileNotFoundError(
                f"Crypto DLL not found: {self.dll_path}"
            )

        # Keep the library loaded for this object's lifetime.
        self._library = ctypes.CDLL(str(self.dll_path))

        self._encrypt = self._configure(
            getattr(self._library, f"{prefix}_encrypt")
        )
        self._decrypt = self._configure(
            getattr(self._library, f"{prefix}_decrypt")
        )

    @staticmethod
    def _configure(function):
        byte_pointer = ctypes.POINTER(ctypes.c_uint8)

        function.argtypes = [
            byte_pointer,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
            byte_pointer,
            ctypes.c_size_t,
            byte_pointer,
            ctypes.c_size_t,
            byte_pointer,
            byte_pointer,
        ]

        function.restype = ctypes.c_int
        return function

    @staticmethod
    def _buffer(data):
        # Empty inputs still receive a valid C address.
        return (
            ctypes.c_uint8 * max(1, len(data))
        ).from_buffer_copy(data if data else b"\x00")

    def _validate(self, data, key, nonce, aad):
        for name, value in (
            ("data", data),
            ("key", key),
            ("nonce", nonce),
            ("aad", aad),
        ):
            if not isinstance(value, bytes):
                raise TypeError(f"{name} must be bytes")

        if len(key) != self.KEY_BYTES:
            raise ValueError(
                f"Key must be {self.KEY_BYTES} bytes"
            )

        if len(nonce) != self.nonce_bytes:
            raise ValueError(
                f"{self.algorithm} nonce must be "
                f"{self.nonce_bytes} bytes"
            )

    @staticmethod
    def _check_status(status):
        if status == 0:
            return

        if status == -3:
            raise AuthenticationError(
                "AEAD authentication failed"
            )

        if status == -1:
            raise ValueError(
                "C crypto function rejected its arguments"
            )

        if status == -2:
            raise RuntimeError(
                "C crypto output buffer is too small"
            )

        raise RuntimeError(
            f"C crypto function failed with status {status}"
        )

    def encrypt(self, plaintext, key, nonce, aad=b""):
        """Return ciphertext followed by the 16-byte tag."""
        self._validate(plaintext, key, nonce, aad)

        capacity = len(plaintext) + self.TAG_BYTES
        output = (ctypes.c_uint8 * capacity)()
        output_len = ctypes.c_size_t(0)

        status = self._encrypt(
            output,
            capacity,
            ctypes.byref(output_len),
            self._buffer(plaintext),
            len(plaintext),
            self._buffer(aad),
            len(aad),
            self._buffer(key),
            self._buffer(nonce),
        )

        self._check_status(status)

        if output_len.value != capacity:
            raise RuntimeError(
                "Unexpected encrypted output length"
            )

        return bytes(output[:output_len.value])

    def decrypt(self, ciphertext, key, nonce, aad=b""):
        """Return plaintext only after successful authentication."""
        self._validate(ciphertext, key, nonce, aad)

        if len(ciphertext) < self.TAG_BYTES:
            raise ValueError(
                "Ciphertext is shorter than the authentication tag"
            )

        expected_length = len(ciphertext) - self.TAG_BYTES
        output = (ctypes.c_uint8 * max(1, expected_length))()
        output_len = ctypes.c_size_t(0)

        status = self._decrypt(
            output,
            expected_length,
            ctypes.byref(output_len),
            self._buffer(ciphertext),
            len(ciphertext),
            self._buffer(aad),
            len(aad),
            self._buffer(key),
            self._buffer(nonce),
        )

        self._check_status(status)

        if output_len.value != expected_length:
            raise RuntimeError(
                "Unexpected decrypted output length"
            )

        return bytes(output[:output_len.value])