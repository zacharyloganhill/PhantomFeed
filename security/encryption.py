"""
Fernet symmetric encryption for scanner/SIEM credential storage.
Key is loaded from PHANTOMFEED_ENCRYPTION_KEY env var at startup.
"""

import base64
import logging
import os

import config

logger = logging.getLogger(__name__)

_fernet = None


def _get_fernet():
    global _fernet
    if _fernet is not None:
        return _fernet
    try:
        from cryptography.fernet import Fernet
        key = config.PHANTOMFEED_ENCRYPTION_KEY.strip()
        if not key:
            key = _auto_key()
        _fernet = Fernet(key.encode() if isinstance(key, str) else key)
        return _fernet
    except Exception as exc:
        logger.error("Encryption init failed: %s", exc)
        raise


def _auto_key() -> str:
    """Generate and persist a key when none is configured — warns loudly."""
    from cryptography.fernet import Fernet
    key_path = os.path.join(os.path.dirname(config.DB_PATH), ".phantomfeed_key")
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            return f.read().decode().strip()
    key = Fernet.generate_key().decode()
    with open(key_path, "w") as f:
        f.write(key)
    logger.warning(
        "PHANTOMFEED_ENCRYPTION_KEY not set — generated auto-key at %s. "
        "Set this key in .env to keep credentials accessible across restarts.",
        key_path,
    )
    return key


def encrypt(plaintext: str) -> str:
    """Encrypt a plaintext string; returns URL-safe base64 token."""
    if not plaintext:
        return ""
    f = _get_fernet()
    return f.encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    """Decrypt a Fernet token; returns plaintext string."""
    if not token:
        return ""
    f = _get_fernet()
    return f.decrypt(token.encode()).decode()


def rotate_key(new_key: str, old_token: str) -> str:
    """Re-encrypt a token with a new key (for key rotation)."""
    from cryptography.fernet import Fernet
    old_fernet = _get_fernet()
    plaintext = old_fernet.decrypt(old_token.encode()).decode()
    new_fernet = Fernet(new_key.encode())
    return new_fernet.encrypt(plaintext.encode()).decode()
