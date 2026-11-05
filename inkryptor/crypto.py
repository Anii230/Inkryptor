"""Portable authenticated encryption for Inkryptor."""

import base64
import json
import os
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Payload configuration
FORMAT_NAME = "inkryptor"
FORMAT_VERSION = 1

KDF_ALGORITHM = "PBKDF2-HMAC-SHA256"
KDF_ITERATIONS = 600_000
SALT_LENGTH = 16
KEY_LENGTH = 32

MIN_ITERATIONS = 100_000
MAX_ITERATIONS = 2_000_000


class EncryptionError(Exception):
    """Raised when encryption fails."""


class DecryptionError(Exception):
    """Raised when decryption fails."""


def _validate_password(password: str) -> None:
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")


def _derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    """Derive a Fernet-compatible key from a password."""

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=iterations,
    )

    derived_key = kdf.derive(password.encode("utf-8"))

    return base64.urlsafe_b64encode(derived_key)


def encrypt_data(data: dict[str, Any], password: str) -> bytes:
    """
    Encrypt a dictionary and return a versioned JSON payload.

    Each encryption operation generates a fresh random salt.
    """

    _validate_password(password)

    if not isinstance(data, dict):
        raise ValueError("Data must be a dictionary.")

    try:
        plaintext = json.dumps(
            data,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

        salt = os.urandom(SALT_LENGTH)

        key = _derive_key(
            password,
            salt,
            KDF_ITERATIONS,
        )

        ciphertext = Fernet(key).encrypt(plaintext)

        envelope = {
            "format": FORMAT_NAME,
            "version": FORMAT_VERSION,
            "kdf": KDF_ALGORITHM,
            "iterations": KDF_ITERATIONS,
            "salt": base64.b64encode(salt).decode("ascii"),
            "ciphertext": ciphertext.decode("ascii"),
        }

        return json.dumps(
            envelope,
            separators=(",", ":"),
        ).encode("utf-8")

    except (TypeError, ValueError) as exc:
        raise EncryptionError("Unable to serialize data.") from exc


def decrypt_data(payload: bytes, password: str) -> dict[str, Any]:
    """
    Validate and decrypt an Inkryptor payload.

    Wrong passwords and modified ciphertexts both produce
    DecryptionError.
    """

    _validate_password(password)

    if not isinstance(payload, bytes):
        raise DecryptionError("Payload must be bytes.")

    try:
        envelope = json.loads(payload.decode("utf-8"))

        if not isinstance(envelope, dict):
            raise DecryptionError("Invalid payload structure.")

        if envelope.get("format") != FORMAT_NAME:
            raise DecryptionError("Unrecognized payload format.")

        if envelope.get("version") != FORMAT_VERSION:
            raise DecryptionError("Unsupported payload version.")

        if envelope.get("kdf") != KDF_ALGORITHM:
            raise DecryptionError("Unsupported key derivation algorithm.")

        iterations = envelope.get("iterations")

        if (
            isinstance(iterations, bool)
            or not isinstance(iterations, int)
            or not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS
        ):
            raise DecryptionError("Invalid KDF parameters.")

        salt = base64.b64decode(
            envelope["salt"],
            validate=True,
        )

        if len(salt) != SALT_LENGTH:
            raise DecryptionError("Invalid salt length.")

        ciphertext = envelope["ciphertext"].encode("ascii")

        key = _derive_key(password, salt, iterations)

        plaintext = Fernet(key).decrypt(ciphertext)

        data = json.loads(plaintext.decode("utf-8"))

        if not isinstance(data, dict):
            raise DecryptionError("Decrypted data is not a dictionary.")

        return data

    except DecryptionError:
        raise

    except (
        InvalidToken,
        KeyError,
        TypeError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise DecryptionError(
            "Decryption failed. The password may be incorrect "
            "or the payload may be corrupted."
        ) from exc
