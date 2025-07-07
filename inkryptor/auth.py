import os
import getpass
import bcrypt
from platformdirs import user_config_path
from pathlib import Path
import hashlib

def get_secure_config_path():
    user = getpass.getuser()
    base = f"{user}_inkryptor_secret"
    filename = hashlib.sha256(base.encode()).hexdigest()[:12]
    return user_config_path(appname="inkryptor") / f".{filename}.cfg"

CONFIG_PATH = get_secure_config_path()

def is_master_password_set():
    return CONFIG_PATH.exists()

def enforce_password_strength(password):
    if len(password) < 12:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    return has_upper and has_lower and has_digit and has_symbol

def set_master_password(password: str):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "wb") as f:
        f.write(hashed)

def verify_master_password(password: str):
    if not is_master_password_set():
        raise ValueError("Master Password Not Set")
    with open(CONFIG_PATH, "rb") as f:
        stored_hash = f.read()
    return bcrypt.checkpw(password.encode(), stored_hash)
