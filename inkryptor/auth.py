"""Master password management for Inkryptor."""

import base64
import hashlib
import os
from pathlib import Path

import bcrypt
from platformdirs import user_config_path


MIN_PASSWORD_LENGTH = 12

CONFIG_DIR = Path(user_config_path("inkryptor"))
CONFIG_PATH = CONFIG_DIR / "master_password.hash"


class AuthError(Exception):
    """Raised when master password authentication fails."""


def enforce_password_strength(password: str) -> bool:
    """Check whether a new master password meets security requirements."""

    if not isinstance(password, str):
        return False

    if len(password) < MIN_PASSWORD_LENGTH:
        return False

    checks = (
        any(char.isupper() for char in password),
        any(char.islower() for char in password),
        any(char.isdigit() for char in password),
        any(not char.isalnum() for char in password),
    )

    return all(checks)


def _prepare_password(password: str) -> bytes:
    """Pre-hash passwords to handle bcrypt's 72-byte input limit."""

    if not isinstance(password, str):
        raise AuthError("Invalid master password.")

    digest = hashlib.sha256(
        b"inkryptor-master-password-v1\0" +
        password.encode("utf-8")
    ).digest()

    return base64.b64encode(digest)


def is_master_password_set() -> bool:
    """Check whether a master password hash exists."""

    return CONFIG_PATH.is_file()


def set_master_password(password: str) -> None:
    """Create and securely store the master password hash."""

    if not enforce_password_strength(password):
        raise AuthError(
            "Password must contain at least 12 characters, "
            "including uppercase, lowercase, digits and symbols."
        )

    CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(CONFIG_DIR, 0o700)

    try:
        hashed = bcrypt.hashpw(
            _prepare_password(password),
            bcrypt.gensalt(rounds=12),
        )

        # O_EXCL prevents accidentally overwriting an existing hash.
        fd = os.open(
            CONFIG_PATH,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )

        try:
            with os.fdopen(fd, "wb") as file:
                file.write(hashed)
                file.flush()
                os.fsync(file.fileno())

        except OSError:
            CONFIG_PATH.unlink(missing_ok=True)
            raise

    except FileExistsError as exc:
        raise AuthError(
            "Master password is already configured."
        ) from exc

    except OSError as exc:
        raise AuthError(
            f"Unable to save master password configuration: {exc}"
        ) from exc


def verify_master_password(password: str) -> bool:
    """Verify a password against the locally stored bcrypt hash."""

    if not is_master_password_set():
        raise AuthError(
            "Master password is not configured. Run setup first."
        )

    try:
        stored_hash = CONFIG_PATH.read_bytes()

        return bcrypt.checkpw(
            _prepare_password(password),
            stored_hash,
        )

    except (OSError, ValueError, TypeError) as exc:
        raise AuthError(
            "Unable to read or verify master password configuration."
        ) from exc
