"""Password hashing using the Python stdlib scrypt KDF.

Using hashlib.scrypt avoids a bcrypt/argon2 dependency that often fails to
build on Windows without a compiler; scrypt is a modern KDF included in the
standard library. Stored format is a PHC-style string:

    scrypt$N=16384,r=8,p=1$<salt hex>$<derived key hex>
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 64


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN,
    )
    return f"scrypt$N={_SCRYPT_N},r={_SCRYPT_R},p={_SCRYPT_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, params, salt_hex, key_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        parsed = dict(p.split("=") for p in params.split(","))
        dk = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(parsed["N"]), r=int(parsed["r"]), p=int(parsed["p"]),
            dklen=len(bytes.fromhex(key_hex)),
        )
        return hmac.compare_digest(dk, bytes.fromhex(key_hex))
    except (ValueError, KeyError, TypeError):
        return False
