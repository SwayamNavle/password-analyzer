"""
report_generator.py
-------------------
Generates a plain-text security report from analysis results.
The report is saved as a .txt file (PDF requires additional libraries).
"""

import os
import time
from datetime import datetime


def generate_report(
    analysis: dict,
    hashes: dict,
    attack_results: dict = None,
    output_dir: str = None,
) -> str:
    """
    Build a comprehensive security analysis report.
    Returns the file path of the saved report.
    """
    if output_dir is None:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        output_dir = os.path.join(base, "exports")
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"password_report_{timestamp}.txt"
    filepath  = os.path.join(output_dir, filename)

    lines = []
    sep   = "=" * 70
    thin  = "-" * 70

    # ── Header ──
    lines += [
        sep,
        "   PASSWORD SECURITY ANALYSIS REPORT",
        f"   Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}",
        sep,
        "",
        "⚠️  CONFIDENTIALITY NOTICE",
        "This report contains sensitive security information.",
        "Do not share or store this file insecurely.",
        "",
        sep,
        "SECTION 1: PASSWORD STRENGTH ANALYSIS",
        sep,
        "",
    ]

    pw = analysis.get("password", "")
    masked = pw[0] + ("*" * (len(pw) - 2)) + pw[-1] if len(pw) > 2 else "***"

    lines += [
        f"  Password (masked):     {masked}",
        f"  Password Length:       {analysis.get('length', 0)} characters",
        f"  Character Set Size:    {analysis.get('charset_size', 0)} unique characters",
        f"  Entropy:               {analysis.get('entropy', 0):.2f} bits",
        f"  Strength Rating:       {analysis.get('strength_label', '—')}",
        f"  Strength Score:        {analysis.get('strength_score', 0)}/100",
        f"  Is Common Password:    {'YES ⚠️' if analysis.get('is_common') else 'No ✓'}",
        "",
        thin,
        "  Rule Checks:",
        thin,
    ]

    rules = analysis.get("rules", {})
    rule_labels = {
        "length_8":       "At least 8 characters",
        "length_12":      "At least 12 characters",
        "length_16":      "At least 16 characters",
        "has_uppercase":  "Contains uppercase letters",
        "has_lowercase":  "Contains lowercase letters",
        "has_digit":      "Contains digits",
        "has_special":    "Contains special characters",
        "no_repeating":   "No repeating characters",
        "no_sequential":  "No sequential patterns",
        "not_common":     "Not a common password",
    }
    for rule_key, label in rule_labels.items():
        status = "✓ PASS" if rules.get(rule_key) else "✗ FAIL"
        lines.append(f"  [{status}]  {label}")

    lines += [
        "",
        thin,
        "  Estimated Crack Times:",
        thin,
    ]
    for attack, t in analysis.get("crack_times", {}).items():
        lines.append(f"  {attack:<30} {t}")

    lines += [
        "",
        thin,
        "  Improvement Suggestions:",
        thin,
    ]
    for sug in analysis.get("suggestions", []):
        lines.append(f"  {sug}")

    # ── Hashes ──
    lines += [
        "",
        sep,
        "SECTION 2: CRYPTOGRAPHIC HASHES",
        sep,
        "",
        "  Note: Hashes are one-way transformations. You cannot reverse a hash",
        "  back to the original password (with a secure algorithm).",
        "",
    ]
    for algo, info in hashes.items():
        if algo.startswith("_"):
            continue
        secure = "✓ Secure" if info.get("secure") else "⚠️  Insecure"
        lines.append(f"  {algo}")
        lines.append(f"    Hash:    {info.get('hash', '—')}")
        lines.append(f"    Status:  {secure}")
        lines.append("")

    # ── Attack Results ──
    if attack_results:
        lines += [
            sep,
            "SECTION 3: ATTACK SIMULATION RESULTS",
            sep,
            "",
        ]
        for attack_name, result in attack_results.items():
            if not isinstance(result, dict):
                continue
            lines += [
                f"  Attack Type:   {result.get('attack_type', attack_name)}",
                f"  Result:        {'CRACKED ⚠️' if result.get('success') else 'NOT CRACKED ✓'}",
                f"  Attempts:      {result.get('attempts', 0):,}",
                f"  Time Taken:    {result.get('elapsed_ms', 0):.2f} ms",
                f"  Speed:         {result.get('speed', 0):,} attempts/sec",
                "",
            ]

    # ── Footer ──
    lines += [
        sep,
        "SECTION 4: SECURITY RECOMMENDATIONS",
        sep,
        "",
        "  1. Use a password manager (Bitwarden, 1Password, KeePass)",
        "  2. Enable Two-Factor Authentication (2FA) everywhere",
        "  3. Use unique passwords for every account",
        "  4. Aim for 16+ character passwords with mixed character types",
        "  5. Never reuse passwords across sites",
        "  6. Regularly check if your email/password has been breached:",
        "     → https://haveibeenpwned.com",
        "",
        sep,
        "END OF REPORT",
        sep,
    ]

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return filepath
