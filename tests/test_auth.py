import os
import stat

import pytest

from inkryptor import auth


# --------------------------------------------------
# Password strength
# --------------------------------------------------

@pytest.mark.parametrize(
    "password",
    [
        "StrongPassword123!",
        "AnotherSecure456@",
        "VeryLongPassword789#",
    ],
)
def test_strong_passwords_are_accepted(password):
    assert auth.enforce_password_strength(password)


@pytest.mark.parametrize(
    "password",
    [
        "",
        "short",
        "lowercasepassword123!",
        "UPPERCASEPASSWORD123!",
        "NoDigitsOrSymbols!",
        "NoSymbols12345",
        "Weak123!",
    ],
)
def test_weak_passwords_are_rejected(password):
    assert not auth.enforce_password_strength(password)


def test_non_string_password_is_rejected():
    assert not auth.enforce_password_strength(None)
    assert not auth.enforce_password_strength(12345)


# --------------------------------------------------
# Test configuration
# --------------------------------------------------

@pytest.fixture
def isolated_config(tmp_path, monkeypatch):
    """Use a temporary configuration directory for each test."""

    config_dir = tmp_path / "inkryptor"
    config_path = config_dir / "master_password.hash"

    monkeypatch.setattr(auth, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(auth, "CONFIG_PATH", config_path)

    return config_dir, config_path


@pytest.fixture
def strong_password():
    return "StrongMasterPassword123!"


# --------------------------------------------------
# Master password setup
# --------------------------------------------------

def test_master_password_is_not_set_initially(isolated_config):
    assert not auth.is_master_password_set()


def test_set_master_password_creates_hash(
    isolated_config,
    strong_password,
):
    config_dir, config_path = isolated_config

    auth.set_master_password(strong_password)

    assert config_path.is_file()
    assert auth.is_master_password_set()
    assert config_path.stat().st_size == 60


def test_stored_hash_is_not_plaintext(
    isolated_config,
    strong_password,
):
    _, config_path = isolated_config

    auth.set_master_password(strong_password)

    stored_hash = config_path.read_bytes()

    assert strong_password.encode() not in stored_hash
    assert stored_hash != strong_password.encode()


def test_weak_password_cannot_be_configured(isolated_config):
    _, config_path = isolated_config

    with pytest.raises(auth.AuthError):
        auth.set_master_password("weak")

    assert not config_path.exists()


def test_existing_master_password_cannot_be_overwritten(
    isolated_config,
    strong_password,
):
    _, config_path = isolated_config

    auth.set_master_password(strong_password)

    original_hash = config_path.read_bytes()

    with pytest.raises(auth.AuthError):
        auth.set_master_password("AnotherSecure456@")

    assert config_path.read_bytes() == original_hash


# --------------------------------------------------
# Master password verification
# --------------------------------------------------

def test_correct_master_password_is_verified(
    isolated_config,
    strong_password,
):
    auth.set_master_password(strong_password)

    assert auth.verify_master_password(strong_password)


def test_incorrect_master_password_is_rejected(
    isolated_config,
    strong_password,
):
    auth.set_master_password(strong_password)

    assert not auth.verify_master_password("WrongPassword123!")


def test_long_password_is_supported(
    isolated_config,
):
    # Longer than bcrypt's original 72-byte input limit.
    password = "A" + ("b" * 100) + "1!"

    auth.set_master_password(password)

    assert auth.verify_master_password(password)


def test_verification_fails_when_password_is_not_configured(
    isolated_config,
):
    with pytest.raises(auth.AuthError):
        auth.verify_master_password("StrongMasterPassword123!")


def test_verification_rejects_non_string_password(
    isolated_config,
    strong_password,
):
    auth.set_master_password(strong_password)

    with pytest.raises(auth.AuthError):
        auth.verify_master_password(None)


# --------------------------------------------------
# Configuration integrity
# --------------------------------------------------

def test_corrupted_hash_is_rejected(
    isolated_config,
):
    config_dir, config_path = isolated_config

    config_dir.mkdir(parents=True)
    config_path.write_bytes(b"invalid-bcrypt-hash")

    with pytest.raises(auth.AuthError):
        auth.verify_master_password("StrongMasterPassword123!")


def test_config_directory_permissions(
    isolated_config,
    strong_password,
):
    config_dir, _ = isolated_config

    auth.set_master_password(strong_password)

    permissions = stat.S_IMODE(config_dir.stat().st_mode)

    if os.name == "posix":
        assert permissions == 0o700


def test_hash_file_permissions(
    isolated_config,
    strong_password,
):
    _, config_path = isolated_config

    auth.set_master_password(strong_password)

    permissions = stat.S_IMODE(config_path.stat().st_mode)

    if os.name == "posix":
        assert permissions == 0o600
