from crypto_bridge import CryptoBridge, AuthenticationError


def check(condition, description):
    if not condition:
        raise RuntimeError(f"[FAIL] {description}")

    print(f"[PASS] {description}")


def test_algorithm(algorithm):
    crypto = CryptoBridge(algorithm)

    # Fixed inputs are for this isolated test only.
    key = bytes(range(16))
    nonce = bytes(range(crypto.nonce_bytes))
    payload = bytes(range(128))
    aad = b"EEG packet header"

    ciphertext = crypto.encrypt(
        payload, key, nonce, aad=aad
    )

    check(
        len(ciphertext) == len(payload) + crypto.TAG_BYTES,
        f"{algorithm}: encrypt through CryptoBridge",
    )

    recovered = crypto.decrypt(
        ciphertext, key, nonce, aad=aad
    )

    check(
        recovered == payload,
        f"{algorithm}: recover original payload",
    )

    modified = bytearray(ciphertext)
    modified[0] ^= 0x01

    try:
        crypto.decrypt(
            bytes(modified), key, nonce, aad=aad
        )
    except AuthenticationError:
        print(f"[PASS] {algorithm}: reject tampering")
    else:
        raise RuntimeError(
            f"[FAIL] {algorithm}: tampered ciphertext accepted"
        )


def main():
    for algorithm in ("ascon", "aes-gcm"):
        test_algorithm(algorithm)

    print("\nAll 6 CryptoBridge checks passed.")


if __name__ == "__main__":
    main()