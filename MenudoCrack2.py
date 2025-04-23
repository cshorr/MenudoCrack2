#!/usr/bin/env python3
import hashlib
import itertools
import string
import os
import sys

def main():
    # Step 1: Get hash
    target_hash = input("Enter the MD5 hash to crack: ").strip()
    if not target_hash or len(target_hash) != 32:
        print("[!] Invalid MD5 hash.")
        sys.exit(1)

    # Step 2: Salt (optional)
    use_salt = input("Use a salt? (y/n): ").strip().lower()
    salt = input("Enter salt: ").strip() if use_salt == 'y' else ""

    # Step 3: Prefix (optional)
    use_prefix = input("Use a prefix? (y/n): ").strip().lower()
    prefix = input("Enter prefix: ").strip() if use_prefix == 'y' else ""

    # Step 4: Digit-only suffix?
    digits_only = input("Use digits only for suffix? (y/n): ").strip().lower() == 'y'
    charset = string.digits if digits_only else string.ascii_uppercase + string.digits

    # Step 5: Suffix length
    try:
        suffix_length = int(input("Enter suffix length (e.g., 4): ").strip())
    except ValueError:
        print("[!] Invalid suffix length.")
        sys.exit(1)

    print(f"[*] Cracking pattern: {prefix}{salt}{{{suffix_length}}} | Charset: {'digits' if digits_only else 'A-Z + 0-9'}")

    for combo in itertools.product(charset, repeat=suffix_length):
        guess = prefix + salt + ''.join(combo)
        if hashlib.md5(guess.encode()).hexdigest() == target_hash:
            print(f"[✔] Success 😄 Password: {guess}")
            with open("cracked_output.txt", "a") as f:
                f.write(f"{target_hash}:{guess}\n")
            break
    else:
        print("[✖] Password not found 😵")

if __name__ == "__main__":
    main()
