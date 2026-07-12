"""
mt_crypto.py — encrypt/decrypt MikroTik API credentials at rest.

Uses a Fernet key stored in the app .env as MT_FERNET_KEY. If the key is
missing, raises a clear error telling the operator to generate one:

    /opt/ipdr/venv/bin/python -c \\
      "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

...then append to /opt/ipdr/.env as:  MT_FERNET_KEY=<that value>
"""

import os
from cryptography.fernet import Fernet


def _key():
    k = os.environ.get("MT_FERNET_KEY")
    if not k:
        # Try reading .env directly (sync script may run outside Flask env).
        env_path = os.environ.get("IPDR_ENV", "/opt/ipdr/.env")
        try:
            with open(env_path) as f:
                for line in f:
                    if line.startswith("MT_FERNET_KEY="):
                        k = line.split("=", 1)[1].strip()
                        break
        except FileNotFoundError:
            pass
    if not k:
        raise RuntimeError(
            "MT_FERNET_KEY not set. Generate one:\n"
            "  /opt/ipdr/venv/bin/python -c "
            "\"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"\n"
            "and append MT_FERNET_KEY=<value> to /opt/ipdr/.env"
        )
    return k.encode() if isinstance(k, str) else k


def encrypt(plaintext):
    return Fernet(_key()).encrypt(plaintext.encode()).decode()


def decrypt(token):
    return Fernet(_key()).decrypt(token.encode()).decode()
