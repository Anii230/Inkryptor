import json

import pytest

from inkryptor.crypto import (
    encrypt_data,
    decrypt_data,
    EncryptionError,
    DecryptionError,
)


TEST_PASSWORD = "StrongPassword123!"


@pytest.fixture
def sample_data():
    return {
        "service": "GitHub",
        "username": "testuser",
        "password": "ExampleSecret123!",
    }


def test_encryption_decryption_roundtrip(sample_data):
    encrypted = encrypt_data(sample_data, TEST_PASSWORD)

    decrypted = decrypt_data(encrypted, TEST_PASSWORD)

    assert decrypted == sample_data


def test_encryption_generates_unique_salts(sample_data):
    first = encrypt_data(sample_data, TEST_PASSWORD)
    second = encrypt_data(sample_data, TEST_PASSWORD)

    first_envelope = json.loads(first)
    second_envelope = json.loads(second)

    assert first_envelope["salt"] != second_envelope["salt"]
    assert first != second


def test_wrong_password_fails(sample_data):
    encrypted = encrypt_data(sample_data, TEST_PASSWORD)

    with pytest.raises(DecryptionError):
        decrypt_data(encrypted, "WrongPassword123!")


def test_tampered_ciphertext_fails(sample_data):
    encrypted = encrypt_data(sample_data, TEST_PASSWORD)
    envelope = json.loads(encrypted)

    token = envelope["ciphertext"]

    replacement = "A" if token[-1] != "A" else "B"
    envelope["ciphertext"] = token[:-1] + replacement

    tampered_payload = json.dumps(envelope).encode()

    with pytest.raises(DecryptionError):
        decrypt_data(tampered_payload, TEST_PASSWORD)


def test_invalid_payload_fails():
    with pytest.raises(DecryptionError):
        decrypt_data(b"not a valid payload", TEST_PASSWORD)


def test_unsupported_version_fails(sample_data):
    encrypted = encrypt_data(sample_data, TEST_PASSWORD)
    envelope = json.loads(encrypted)

    envelope["version"] = 999

    with pytest.raises(DecryptionError):
        decrypt_data(
            json.dumps(envelope).encode(),
            TEST_PASSWORD,
        )


def test_non_dictionary_data_fails():
    with pytest.raises(ValueError):
        encrypt_data("not a dictionary", TEST_PASSWORD)


def test_empty_password_fails(sample_data):
    with pytest.raises(ValueError):
        encrypt_data(sample_data, "")


def test_payload_contains_expected_metadata(sample_data):
    encrypted = encrypt_data(sample_data, TEST_PASSWORD)
    envelope = json.loads(encrypted)

    assert envelope["format"] == "inkryptor"
    assert envelope["version"] == 1
    assert envelope["kdf"] == "PBKDF2-HMAC-SHA256"
    assert envelope["iterations"] == 600_000
    assert "salt" in envelope
    assert "ciphertext" in envelope
