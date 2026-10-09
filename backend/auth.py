import hashlib
import secrets
from pathlib import Path
import json


BASE_DIR = Path(__file__).resolve().parent.parent
AUTH_FILE = BASE_DIR / "backend" / "analysts.json"


def hash_password(password, salt=None):
    """
    Hash a password using PBKDF2-HMAC-SHA256.
    A random salt is generated for new passwords.
    """

    if salt is None:
        salt = secrets.token_hex(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        200_000
    ).hex()

    return salt, password_hash


def verify_password(password, salt, stored_hash):
    """
    Verify a password against the stored PBKDF2 hash.
    """

    _, calculated_hash = hash_password(password, salt)

    return secrets.compare_digest(
        calculated_hash,
        stored_hash
    )


def create_default_analyst():
    """
    Create a default analyst account if one does not exist.
    """

    if AUTH_FILE.exists():
        return

    salt, password_hash = hash_password("admin123")

    analysts = {
        "analyst": {
            "password_hash": password_hash,
            "salt": salt,
            "role": "SOC Analyst"
        }
    }

    AUTH_FILE.write_text(
        json.dumps(analysts, indent=4),
        encoding="utf-8"
    )


def authenticate(username, password):
    """
    Authenticate an analyst.
    """

    create_default_analyst()

    try:
        analysts = json.loads(
            AUTH_FILE.read_text(encoding="utf-8")
        )
    except Exception:
        return False, None

    analyst = analysts.get(username)

    if not analyst:
        return False, None

    valid = verify_password(
        password,
        analyst["salt"],
        analyst["password_hash"]
    )

    if valid:
        return True, {
            "username": username,
            "role": analyst.get("role", "SOC Analyst")
        }

    return False, None