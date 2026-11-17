#!/usr/bin/env python3
"""Offline password strength checker.

Checks a password against length, character variety, common-password and
pattern heuristics. Everything runs locally; nothing is stored or sent.
"""

import argparse
import getpass
import json
import math
import re
import string
import sys

# Small built-in list of very common passwords. A bigger local wordlist can
# be supplied with --wordlist.
COMMON_PASSWORDS = {
    "password", "123456", "1234567", "12345678", "123456789", "1234567890",
    "12345", "qwerty", "abc123", "football", "monkey", "letmein", "dragon",
    "111111", "baseball", "iloveyou", "trustno1", "sunshine", "master",
    "welcome", "shadow", "ashley", "michael", "ninja", "mustang",
    "password1", "admin", "root", "login", "passw0rd", "p@ssw0rd",
    "starwars", "whatever", "freedom", "qazwsx", "654321", "superman",
    "1qaz2wsx", "qwerty123", "000000", "princess", "hottie", "loveme",
}

KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")

VERDICTS = ["very weak", "weak", "fair", "strong", "very strong"]


def charset_size(password):
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c in string.digits for c in password):
        size += 10
    if any(not c.isalnum() for c in password):
        size += 32
    return size


def entropy_bits(password):
    size = charset_size(password)
    if size == 0 or not password:
        return 0.0
    return round(len(password) * math.log2(size), 1)


def has_sequence(password, run=4):
    low = password.lower()
    sources = [string.ascii_lowercase, string.digits] + list(KEYBOARD_ROWS)
    for src in sources:
        for i in range(len(src) - run + 1):
            chunk = src[i:i + run]
            if chunk in low or chunk[::-1] in low:
                return True
    return False


def has_repeat(password, run=3):
    return bool(re.search(r"(.)\1{%d,}" % (run - 1), password))


def looks_like_year_or_date(password):
    if re.search(r"(19|20)\d{2}", password):
        return True
    return bool(re.fullmatch(r"\d{6,8}", password))


def analyze(password):
    findings = []
    suggestions = []
    score = 0
    length = len(password)

    if length == 0:
        return {
            "score": 0,
            "verdict": VERDICTS[0],
            "entropy_bits": 0.0,
            "findings": ["empty password"],
            "suggestions": ["enter a password"],
        }

    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if length >= 16:
        score += 1
    elif length < 12:
        suggestions.append("use at least 12 characters")

    classes = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ])
    if classes >= 3:
        score += 1
    if classes == 4:
        score += 1
    elif classes < 3:
        suggestions.append("mix upper/lowercase letters, digits and symbols")

    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        findings.append("this is a commonly used password")
        suggestions.append("avoid common passwords")
        score = 0
    else:
        if has_sequence(password):
            findings.append("contains a keyboard or alphabetical sequence")
            suggestions.append("avoid sequences like abcd, 1234 or qwer")
            score -= 1
        if has_repeat(password):
            findings.append("contains repeated characters")
            suggestions.append("avoid repeating the same character")
            score -= 1
        if looks_like_year_or_date(password):
            findings.append("looks like a date or year")
            suggestions.append("avoid dates and years")
            score -= 1

    ent = entropy_bits(password)
    if ent >= 80:
        score += 1
    elif ent < 40 and lowered not in COMMON_PASSWORDS:
        suggestions.append("longer passphrases raise entropy more than symbols")

    score = max(0, min(4, score))
    if not findings:
        findings.append("no obvious weaknesses found")
    if not suggestions:
        suggestions.append("store it in a password manager and enable 2FA")

    return {
        "score": score,
        "verdict": VERDICTS[score],
        "entropy_bits": ent,
        "findings": findings,
        "suggestions": suggestions,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check password strength locally. Nothing is sent anywhere."
    )
    parser.add_argument("password", nargs="?",
                        help="password to check (omit to be prompted without echo)")
    parser.add_argument("--json", action="store_true",
                        help="print the result as JSON")
    parser.add_argument("--wordlist",
                        help="path to a local text file of banned passwords, one per line")
    args = parser.parse_args(argv)

    if args.wordlist:
        try:
            with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as fh:
                COMMON_PASSWORDS.update(
                    line.strip().lower() for line in fh if line.strip())
        except OSError as exc:
            print("could not read wordlist: %s" % exc, file=sys.stderr)
            return 2

    if args.password is not None:
        password = args.password
        print("note: passing a password as an argument can expose it in your "
              "shell history; omit it to be prompted safely.", file=sys.stderr)
    else:
        password = getpass.getpass("Password to check: ")

    result = analyze(password)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("Verdict:  %s (%d/4)" % (result["verdict"], result["score"]))
        print("Entropy:  ~%s bits" % result["entropy_bits"])
        print("Findings:")
        for item in result["findings"]:
            print("  - %s" % item)
        print("Suggestions:")
        for item in result["suggestions"]:
            print("  - %s" % item)
    return 0


if __name__ == "__main__":
    sys.exit(main())
