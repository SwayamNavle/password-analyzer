"""
strength_analyzer.py
--------------------
Analyzes password strength using entropy calculations and rule-based checks.
Provides feedback, crack time estimates, and improvement suggestions.
"""

import math
import re
import string


# ── Common password list (quick lookup) ──────────────────────────────────────
COMMON_PASSWORDS = {
    "password", "123456", "password123", "admin", "letmein", "welcome",
    "monkey", "dragon", "master", "sunshine", "princess", "football",
    "shadow", "superman", "qwerty", "iloveyou", "trustno1", "hunter2",
    "baseball", "batman", "abc123", "passw0rd", "test123", "password1",
    "123456789", "12345678", "12345", "111111", "000000", "qwerty123",
    "login", "pass", "secret", "guest", "root", "changeme", "default",
    "admin123", "administrator", "starwars", "mustang", "freedom"
}

# ── Scoring weights ───────────────────────────────────────────────────────────
LENGTH_THRESHOLDS = {
    6:  ("Very Short",  0),
    8:  ("Short",       1),
    10: ("Moderate",    2),
    14: ("Good",        3),
    20: ("Excellent",   4),
}

# How many guesses per second for different attack types
ATTACK_SPEEDS = {
    "Online (throttled)":    100,
    "Online (fast)":         1_000,
    "Offline (MD5)":         10_000_000_000,
    "Offline (bcrypt)":      10_000,
    "Offline (SHA-256)":     8_000_000_000,
}


# ── Core Analysis Functions ───────────────────────────────────────────────────

def calculate_charset_size(password: str) -> int:
    """Return the effective character-set size used in the password."""
    size = 0
    if re.search(r'[a-z]', password):
        size += 26
    if re.search(r'[A-Z]', password):
        size += 26
    if re.search(r'\d', password):
        size += 10
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?`~ ]', password):
        size += 32
    return max(size, 1)


def calculate_entropy(password: str) -> float:
    """
    Shannon entropy: H = L * log2(N)
    Where L = length, N = charset size.
    Returns bits of entropy.
    """
    charset_size = calculate_charset_size(password)
    length = len(password)
    if length == 0:
        return 0.0
    return length * math.log2(charset_size)


def estimate_crack_time(entropy: float, speed: int = 1_000_000_000) -> dict:
    """
    Estimate crack time given entropy (bits) and guesses/sec.
    Returns human-readable times for multiple attack vectors.
    """
    # Total combinations = 2^entropy
    total_combinations = 2 ** entropy
    results = {}

    for attack_name, guesses_per_sec in ATTACK_SPEEDS.items():
        seconds = total_combinations / (2 * guesses_per_sec)  # avg = half space
        results[attack_name] = _format_time(seconds)

    return results


def _format_time(seconds: float) -> str:
    """Convert raw seconds to a human-friendly string."""
    if seconds < 1:
        return "< 1 second"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    elif seconds < 86400 * 30:
        return f"{seconds/86400:.1f} days"
    elif seconds < 86400 * 365:
        return f"{seconds/(86400*30):.1f} months"
    elif seconds < 86400 * 365 * 1000:
        return f"{seconds/(86400*365):.1f} years"
    elif seconds < 86400 * 365 * 1_000_000:
        return f"{seconds/(86400*365*1000):.1f} thousand years"
    elif seconds < 86400 * 365 * 1_000_000_000:
        return f"{seconds/(86400*365*1_000_000):.1f} million years"
    else:
        return f"{seconds/(86400*365*1_000_000_000):.2f} billion years"


def check_rules(password: str) -> dict:
    """
    Returns a dict of rule checks with True/False values.
    """
    return {
        "length_8":       len(password) >= 8,
        "length_12":      len(password) >= 12,
        "length_16":      len(password) >= 16,
        "has_uppercase":  bool(re.search(r'[A-Z]', password)),
        "has_lowercase":  bool(re.search(r'[a-z]', password)),
        "has_digit":      bool(re.search(r'\d', password)),
        "has_special":    bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?`~]', password)),
        "no_spaces":      ' ' not in password,
        "no_repeating":   not bool(re.search(r'(.)\1{2,}', password)),
        "no_sequential":  not _has_sequential(password),
        "not_common":     password.lower() not in COMMON_PASSWORDS,
    }


def _has_sequential(password: str) -> bool:
    """Detect keyboard walks or sequential chars like 'abcd', '1234', 'qwerty'."""
    seq_patterns = [
        "abcdefghijklmnopqrstuvwxyz",
        "zyxwvutsrqponmlkjihgfedcba",
        "0123456789",
        "9876543210",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
    ]
    pwd_lower = password.lower()
    for pattern in seq_patterns:
        for i in range(len(pattern) - 2):
            if pattern[i:i+3] in pwd_lower:
                return True
    return False


def get_strength_label(entropy: float, rules: dict) -> tuple[str, int, str]:
    """
    Returns (label, score 0-100, color_class).
    """
    # Base score on entropy
    if entropy < 28:
        score = int((entropy / 28) * 20)
    elif entropy < 36:
        score = 20 + int(((entropy - 28) / 8) * 20)
    elif entropy < 60:
        score = 40 + int(((entropy - 36) / 24) * 25)
    elif entropy < 80:
        score = 65 + int(((entropy - 60) / 20) * 20)
    else:
        score = min(85 + int((entropy - 80) / 5), 100)

    # Penalise rule violations
    penalties = {
        "no_repeating": -10,
        "no_sequential": -10,
        "not_common": -40,
    }
    for rule, penalty in penalties.items():
        if not rules.get(rule, True):
            score = max(0, score + penalty)

    # Bonus for extra rules
    if rules.get("length_16") and rules.get("has_special"):
        score = min(score + 5, 100)

    score = max(0, min(score, 100))

    if score < 20:
        return "Very Weak", score, "red"
    elif score < 40:
        return "Weak", score, "orange"
    elif score < 60:
        return "Fair", score, "yellow"
    elif score < 80:
        return "Strong", score, "blue"
    else:
        return "Very Strong", score, "green"


def generate_suggestions(password: str, rules: dict) -> list[str]:
    """Return actionable improvement suggestions."""
    suggestions = []

    if not rules["length_8"]:
        suggestions.append("🔴 Use at least 8 characters — longer is always better.")
    elif not rules["length_12"]:
        suggestions.append("🟡 Increase to 12+ characters for significantly better protection.")
    elif not rules["length_16"]:
        suggestions.append("🔵 Consider 16+ characters for near-uncrackable strength.")

    if not rules["has_uppercase"]:
        suggestions.append("🔴 Add uppercase letters (A–Z) to expand the character set.")
    if not rules["has_lowercase"]:
        suggestions.append("🔴 Include lowercase letters (a–z).")
    if not rules["has_digit"]:
        suggestions.append("🟡 Add at least one number (0–9).")
    if not rules["has_special"]:
        suggestions.append("🟡 Include special characters like !@#$%^&* for a big entropy boost.")
    if not rules["no_repeating"]:
        suggestions.append("🔴 Avoid repeated characters (e.g. 'aaa', '111').")
    if not rules["no_sequential"]:
        suggestions.append("🔴 Avoid sequential patterns (e.g. '1234', 'qwerty', 'abcd').")
    if not rules["not_common"]:
        suggestions.append("🚨 This password appears in common password lists — change it immediately!")

    if not suggestions:
        suggestions.append("✅ Excellent password! Consider using a password manager to store it safely.")

    return suggestions


def analyze_password(password: str) -> dict:
    """
    Master function — runs all checks and returns a comprehensive result dict.
    """
    if not password:
        return {
            "password": "",
            "length": 0,
            "charset_size": 0,
            "entropy": 0.0,
            "strength_label": "—",
            "strength_score": 0,
            "strength_color": "gray",
            "rules": {},
            "crack_times": {},
            "suggestions": ["Enter a password to begin analysis."],
            "is_common": False,
        }

    rules = check_rules(password)
    entropy = calculate_entropy(password)
    label, score, color = get_strength_label(entropy, rules)
    crack_times = estimate_crack_time(entropy)
    suggestions = generate_suggestions(password, rules)

    return {
        "password": password,
        "length": len(password),
        "charset_size": calculate_charset_size(password),
        "entropy": round(entropy, 2),
        "strength_label": label,
        "strength_score": score,
        "strength_color": color,
        "rules": rules,
        "crack_times": crack_times,
        "suggestions": suggestions,
        "is_common": password.lower() in COMMON_PASSWORDS,
    }


def compare_passwords(pw1: str, pw2: str) -> dict:
    """Compare two passwords side-by-side."""
    a1 = analyze_password(pw1)
    a2 = analyze_password(pw2)
    return {
        "password_1": a1,
        "password_2": a2,
        "winner": "Password 2" if a2["entropy"] > a1["entropy"] else "Password 1",
        "entropy_diff": abs(a2["entropy"] - a1["entropy"]),
    }
