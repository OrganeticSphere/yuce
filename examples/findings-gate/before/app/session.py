"""Session cookies of a small shop."""
import hashlib

SECRET_KEY = "dev-secret"


def sign(value):
    return hashlib.sha256((SECRET_KEY + value).encode()).hexdigest()
