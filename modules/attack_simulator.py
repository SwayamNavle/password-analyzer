"""
attack_simulator.py
-------------------
Simulates common password cracking attacks for educational purposes.

Implements:
 1. Dictionary Attack  — tries words from a wordlist
 2. Brute Force Attack — tries all combinations up to a length limit
 3. Hybrid Attack      — dictionary words with number/symbol suffixes

⚠️  For educational demonstration only.
"""

import itertools
import string
import time
import os
from typing import Generator


# ── Wordlist Loading ──────────────────────────────────────────────────────────

def load_wordlist(path: str = None) -> list[str]:
    """Load words from a file, one per line. Falls back to built-in list."""
    if path is None:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(base, "data", "wordlist.txt")

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()]
        return words
    except FileNotFoundError:
        return _builtin_wordlist()


def _builtin_wordlist() -> list[str]:
    return [
        "password", "123456", "password123", "admin", "letmein",
        "welcome", "monkey", "dragon", "master", "sunshine",
        "princess", "football", "shadow", "superman", "qwerty",
        "iloveyou", "trustno1", "hunter2", "baseball", "batman",
        "abc123", "passw0rd", "test123", "password1", "12345678",
        "111111", "qwerty123", "login", "pass", "secret", "guest",
    ]


# ── Dictionary Attack ─────────────────────────────────────────────────────────

def dictionary_attack(
    target_password: str,
    wordlist: list[str] = None,
    max_attempts: int = 10_000,
) -> dict:
    """
    Try each word in the wordlist against the target.
    Returns result dict with timing, attempt count, and result.
    """
    if wordlist is None:
        wordlist = load_wordlist()

    target = target_password  # Case-sensitive (realistic)
    attempts = 0
    start_time = time.perf_counter()
    log = []

    for word in wordlist[:max_attempts]:
        attempts += 1

        # Try the word as-is
        if word == target:
            elapsed = time.perf_counter() - start_time
            log.append(f"✅ Cracked on attempt #{attempts}: '{word}'")
            return _result(True, word, attempts, elapsed, log, "Dictionary")

        # Try lowercase and title case
        for variant in [word.lower(), word.capitalize()]:
            attempts += 1
            if variant == target:
                elapsed = time.perf_counter() - start_time
                log.append(f"✅ Cracked on attempt #{attempts}: '{variant}' (variant of '{word}')")
                return _result(True, variant, attempts, elapsed, log, "Dictionary")

        if attempts % 50 == 0:
            log.append(f"   Tried {attempts} words... still searching")

    elapsed = time.perf_counter() - start_time
    log.append(f"❌ Not found after {attempts} attempts.")
    return _result(False, None, attempts, elapsed, log, "Dictionary")


# ── Brute Force Attack ────────────────────────────────────────────────────────

def brute_force_attack(
    target_password: str,
    charset: str = None,
    max_length: int = 4,
    max_attempts: int = 500_000,
) -> dict:
    """
    Try all character combinations up to max_length.
    Limited by max_attempts to prevent UI freezing.
    """
    if charset is None:
        charset = string.ascii_lowercase + string.digits

    attempts  = 0
    start_time = time.perf_counter()
    log = [f"🔍 Brute force started | charset: {len(charset)} chars | max length: {max_length}"]

    for length in range(1, max_length + 1):
        log.append(f"   Trying length {length}... ({len(charset)**length:,} combinations)")

        for combo in itertools.product(charset, repeat=length):
            candidate = ''.join(combo)
            attempts += 1

            if candidate == target_password:
                elapsed = time.perf_counter() - start_time
                log.append(f"✅ Cracked: '{candidate}' in {attempts:,} attempts!")
                return _result(True, candidate, attempts, elapsed, log, "Brute Force")

            if attempts >= max_attempts:
                elapsed = time.perf_counter() - start_time
                log.append(f"⚠️  Stopped at {max_attempts:,} attempt limit. Too many combinations.")
                return _result(False, None, attempts, elapsed, log, "Brute Force")

    elapsed = time.perf_counter() - start_time
    log.append(f"❌ Not found after exhausting all combinations up to length {max_length}.")
    return _result(False, None, attempts, elapsed, log, "Brute Force")


# ── Hybrid Attack ─────────────────────────────────────────────────────────────

def hybrid_attack(
    target_password: str,
    wordlist: list[str] = None,
    max_attempts: int = 50_000,
) -> dict:
    """
    Combines dictionary words with common suffixes (numbers, symbols, years).
    This is a realistic attack against 'smartened-up' common passwords.
    """
    if wordlist is None:
        wordlist = load_wordlist()

    # Common transformations attackers use
    suffixes = (
        [""] +
        [str(n) for n in range(0, 100)] +
        ["!", "!!", "@", "#", "$", "1!", "123", "1234", "12345"] +
        ["2022", "2023", "2024", "2025", "2026"] +
        ["1!", "2!", "3!", "!", "@1"]
    )

    # L33tspeak substitutions
    leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '+'}

    def leet(word):
        return ''.join(leet_map.get(c.lower(), c) for c in word)

    attempts  = 0
    start_time = time.perf_counter()
    log = [f"🔀 Hybrid attack started | {len(wordlist)} base words × transformations"]

    for word in wordlist:
        variants = [
            word,
            word.lower(),
            word.upper(),
            word.capitalize(),
            leet(word),
            word[::-1],          # reversed
        ]

        for variant in variants:
            for suffix in suffixes:
                candidate = variant + suffix
                attempts += 1

                if candidate == target_password:
                    elapsed = time.perf_counter() - start_time
                    log.append(f"✅ Cracked: '{candidate}' in {attempts:,} attempts!")
                    return _result(True, candidate, attempts, elapsed, log, "Hybrid")

                if attempts >= max_attempts:
                    elapsed = time.perf_counter() - start_time
                    log.append(f"⚠️  Stopped at {max_attempts:,} attempt limit.")
                    return _result(False, None, attempts, elapsed, log, "Hybrid")

    elapsed = time.perf_counter() - start_time
    log.append(f"❌ Not found after {attempts:,} attempts.")
    return _result(False, None, attempts, elapsed, log, "Hybrid")


# ── Full Simulation ───────────────────────────────────────────────────────────

def run_all_attacks(target_password: str, wordlist: list[str] = None) -> dict:
    """Run all three attacks and return combined results."""
    if wordlist is None:
        wordlist = load_wordlist()

    return {
        "dictionary": dictionary_attack(target_password, wordlist),
        "brute_force": brute_force_attack(target_password),
        "hybrid":      hybrid_attack(target_password, wordlist),
    }


def estimate_real_crack_time(password: str) -> dict:
    """
    Estimate real-world crack time for a password (not just simulation).
    Based on entropy and realistic attack speeds.
    """
    from modules.strength_analyzer import calculate_entropy, estimate_crack_time
    entropy = calculate_entropy(password)
    return estimate_crack_time(entropy)


# ── Internal Helper ───────────────────────────────────────────────────────────

def _result(
    success: bool,
    found: str | None,
    attempts: int,
    elapsed: float,
    log: list[str],
    attack_type: str,
) -> dict:
    """Build a standardised result dict."""
    return {
        "success":     success,
        "found":       found,
        "attempts":    attempts,
        "elapsed_sec": round(elapsed, 4),
        "elapsed_ms":  round(elapsed * 1000, 2),
        "speed":       int(attempts / elapsed) if elapsed > 0 else 0,
        "log":         log,
        "attack_type": attack_type,
        "summary": (
            f"✅ Cracked '{found}' in {attempts:,} attempts ({elapsed*1000:.1f} ms)"
            if success else
            f"❌ Not cracked after {attempts:,} attempts ({elapsed*1000:.1f} ms)"
        ),
    }
