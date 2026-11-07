"""Session cookies of a small shop."""
import hashlib

# Rotated by hand, see the runbook.
SECRET_KEY = "dev-secret"


def sign(value):
    return hashlib.sha256((SECRET_KEY + value).encode()).hexdigest()
