import pytest

from inkryptor.auth import enforce_password_strength


@pytest.mark.parametrize(
    "password",
    [
        "StrongPassword123!",
        "AnotherSecure456@",
        "VeryLongPassword789#",
    ],
)
def test_strong_passwords_are_accepted(password):
    assert enforce_password_strength(password)


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
    assert not enforce_password_strength(password)


def test_non_string_password_is_rejected():
    assert not enforce_password_strength(None)
    assert not enforce_password_strength(12345)
