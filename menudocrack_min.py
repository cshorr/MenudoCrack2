#!/usr/bin/env python3
import hashlib
import itertools
import string

# Hardcoded hash of SKY-HQNT-1234 (MD5)
target_hash = "71b816fe0b7b763d889ecc227eab400a"
prefix = "SKY-HQNT-"
charset = string.digits
suffix_length = 4

print("[*] Cracking MD5 with digits only (suffix length = 4)...")

for combo in itertools.product(charset, repeat=suffix_length):
    candidate = prefix + ''.join(combo)
    hashed = hashlib.md5(candidate.encode()).hexdigest()
    if hashed == target_hash:
        print(f"[✔] Success 😄 Password: {candidate}")
        break
else:
    print("[✖] Password not found 😵")
