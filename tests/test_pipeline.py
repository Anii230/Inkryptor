import pytest

from PIL import Image

from inkryptor.crypto import (
    encrypt_data,
    decrypt_data,
    DecryptionError,
)

from inkryptor.embed import embed_payload
from inkryptor.extract import extract_payload


@pytest.fixture
def cover_image(tmp_path):
    path = tmp_path / "cover.png"

    image = Image.new("RGB", (128, 128), color=(120, 160, 200))
    image.save(path)
    image.close()

    return path


@pytest.fixture
def credentials():
    return {
        "service": "GitHub",
        "username": "ani2305",
        "password": "ExampleSecret123!",
    }


def test_complete_encryption_steganography_pipeline(
    cover_image, credentials, tmp_path
):
    master_password = "StrongMasterPassword123!"

    encrypted = encrypt_data(credentials, master_password)

    stego_path = tmp_path / "inkryptor_output.png"

    embed_payload(encrypted, cover_image, stego_path)

    extracted = extract_payload(stego_path)

    recovered = decrypt_data(extracted, master_password)

    assert recovered == credentials


def test_pipeline_rejects_wrong_master_password(
    cover_image, credentials, tmp_path
):
    encrypted = encrypt_data(
        credentials,
        "StrongMasterPassword123!",
    )

    stego_path = tmp_path / "inkryptor_output.png"

    embed_payload(encrypted, cover_image, stego_path)

    extracted = extract_payload(stego_path)

    with pytest.raises(DecryptionError):
        decrypt_data(extracted, "WrongPassword123!")


def test_pipeline_supports_multiple_credentials(
    cover_image, tmp_path
):
    credentials = {
        "credentials": [
            {
                "service": "GitHub",
                "username": "ani2305",
                "password": "SecretOne123!",
            },
            {
                "service": "Google",
                "username": "ani@example.com",
                "password": "SecretTwo456!",
            },
        ]
    }

    password = "StrongMasterPassword123!"

    encrypted = encrypt_data(credentials, password)

    stego_path = tmp_path / "multiple_credentials.png"

    embed_payload(encrypted, cover_image, stego_path)

    extracted = extract_payload(stego_path)

    assert decrypt_data(extracted, password) == credentials
