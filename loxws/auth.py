"""Authentication helpers for Loxone token/JWT flows."""

from __future__ import annotations

import binascii
import hashlib
import hmac


def normalize_hash_algorithm(hash_alg: str | None) -> str:
    """Normalize supported algorithm labels to hashlib names."""
    if not hash_alg:
        return "sha256"
    normalized = hash_alg.strip().lower()
    if normalized in {"sha1", "sha-1"}:
        return "sha1"
    if normalized in {"sha256", "sha-256"}:
        return "sha256"
    raise ValueError(f"Unsupported hash algorithm: {hash_alg}")


def hash_password(password: str, user_salt: str, hash_alg: str) -> str:
    """Create an upper-case password hash from password and user salt."""
    algo = normalize_hash_algorithm(hash_alg)
    hasher = hashlib.new(algo)
    hasher.update(f"{password}:{user_salt}".encode("utf-8"))
    return hasher.hexdigest().upper()


def build_auth_hash(username: str, password_hash: str, key_hex: str, hash_alg: str) -> str:
    """Create user-bound HMAC hash for getjwt/authwithtoken calls."""
    algo = normalize_hash_algorithm(hash_alg)
    digestmod = getattr(hashlib, algo)
    secret = binascii.unhexlify(key_hex)
    payload = f"{username}:{password_hash}".encode("utf-8")
    return hmac.new(secret, payload, digestmod).hexdigest()
