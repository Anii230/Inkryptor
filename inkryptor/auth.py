"""Master password validation for Inkryptor."""

import re


MIN_PASSWORD_LENGTH = 12


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
