"""
hash_generator.py
-----------------
Generates cryptographic hashes for passwords using multiple algorithms.
Provides educational context on why hashing is used in security.
"""

import hashlib
import hmac
import os
import base64
import time


# ── Hash Generation ───────────────────────────────────────────────────────────

def hash_sha256(password: str) -> str:
    """Generate SHA-256 hash of a password."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def hash_sha512(password: str) -> str:
    """Generate SHA-512 hash of a password."""
    return hashlib.sha512(password.encode('utf-8')).hexdigest()


def hash_md5(password: str) -> str:
    """Generate MD5 hash — included for education (NOT secure for passwords)."""
    return hashlib.md5(password.encode('utf-8')).hexdigest()


def hash_sha1(password: str) -> str:
    """Generate SHA-1 hash — included for education (deprecated for passwords)."""
    return hashlib.sha1(password.encode('utf-8')).hexdigest()


def hash_with_salt_sha256(password: str, salt: str = None) -> dict:
    """
    Generate a salted SHA-256 hash.
    If no salt is provided, a random 16-byte salt is generated.
    Returns dict with salt and hash.
    """
    if salt is None:
        salt = base64.b64encode(os.urandom(16)).decode('utf-8')

    salted = (salt + password).encode('utf-8')
    hashed = hashlib.sha256(salted).hexdigest()

    return {
        "salt": salt,
        "hash": hashed,
        "combined": f"{salt}:{hashed}",
    }


def generate_all_hashes(password: str) -> dict:
    """
    Generate hashes using multiple algorithms for comparison/education.
    Returns a dict with algorithm name → hash value.
    """
    if not password:
        return {}

    start = time.perf_counter()
    sha256 = hash_sha256(password)
    sha512 = hash_sha512(password)
    md5    = hash_md5(password)
    sha1   = hash_sha1(password)
    salted = hash_with_salt_sha256(password)
    elapsed = time.perf_counter() - start

    return {
        "MD5 (insecure)":         {"hash": md5,    "bits": 128, "secure": False},
        "SHA-1 (deprecated)":     {"hash": sha1,   "bits": 160, "secure": False},
        "SHA-256 (recommended)":  {"hash": sha256, "bits": 256, "secure": True},
        "SHA-512 (strong)":       {"hash": sha512, "bits": 512, "secure": True},
        "SHA-256 + Salt":         {"hash": salted["combined"], "bits": 256, "secure": True},
        "_time_ms":               round(elapsed * 1000, 4),
    }


def verify_hash(password: str, stored_hash: str, algorithm: str = "sha256") -> bool:
    """
    Verify a password against a stored hash.
    Supports: sha256, sha512, md5, sha1.
    """
    algorithms = {
        "sha256": hash_sha256,
        "sha512": hash_sha512,
        "md5":    hash_md5,
        "sha1":   hash_sha1,
    }
    fn = algorithms.get(algorithm.lower())
    if fn is None:
        raise ValueError(f"Unknown algorithm: {algorithm}")
    return hmac.compare_digest(fn(password), stored_hash)


# ── Educational Content ───────────────────────────────────────────────────────

HASH_EDUCATION = {
    "why_hash": """
**Why do we hash passwords?**

Storing passwords in plain text is catastrophic — if a database is breached, every 
account is compromised instantly. Hashing transforms a password into a fixed-length 
fingerprint that **cannot be reversed** (in theory). When you log in, your input is 
hashed and compared to the stored hash — the real password never needs to be stored.

Key properties of a good hash function:
- **Deterministic**: Same input always produces the same output
- **One-way**: Cannot reverse the hash back to the original
- **Avalanche effect**: Changing one character completely changes the hash
- **Collision resistant**: Two different inputs shouldn't produce the same hash
""",

    "why_salt": """
**What is a Salt?**

A salt is a random string added to a password BEFORE hashing. Without salting:
- If two users have the same password, they get the same hash
- Attackers use **Rainbow Tables** (pre-computed hash→password databases) to reverse hashes instantly

With a unique salt per user:
- Identical passwords produce completely different hashes
- Rainbow tables become useless (they'd need to recompute for every salt)
- Each password must be cracked individually

Example:
- Password: "hello123"
- Salt: "xK9#mP2q"
- Salted password: "xK9#mP2qhello123"
- Final hash: (completely different from unsalted hash)
""",

    "algorithms_compared": {
        "MD5": "128-bit. Created 1991. BROKEN — collisions found. Never use for passwords.",
        "SHA-1": "160-bit. Created 1995. DEPRECATED — collision attacks proven. Avoid.",
        "SHA-256": "256-bit. Part of SHA-2 family. Currently secure. Good for general use.",
        "SHA-512": "512-bit. More secure than SHA-256. Slightly slower. Great for passwords.",
        "bcrypt": "Adaptive hash — deliberately slow. Industry standard for passwords.",
        "Argon2": "Modern standard. Memory-hard. Recommended by OWASP for new systems.",
    }
}
