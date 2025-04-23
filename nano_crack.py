import hashlib

# -------- Config --------
HASH_FILE = r"P:\Hacking.py_P\nanohash.txt"  # Correct path to your file
WORDLIST = r"P:\Hacking.py_Wordlist\rockyou.txt"  # Your working wordlist path

# ------------------------
def ntlm_hash(word):
    return hashlib.new('md4', word.encode('utf-16le')).hexdigest().upper()

# Load hash pairs
with open(HASH_FILE, "r") as f:
    hash_lines = [line.strip() for line in f if ':' in line]

# Build lookup table: {NTLM hash: original hash part}
hash_lookup = {}
for line in hash_lines:
    part1, ntlm = line.split(":")
    hash_lookup[ntlm.upper()] = part1

print(f"Loaded {len(hash_lookup)} NTLM hashes to crack.\n")

# Crack time
with open(WORDLIST, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        pwd = line.strip()
        if not pwd:
            continue
        hashed = ntlm_hash(pwd)
        if hashed in hash_lookup:
            print(f"[+] Cracked: {hash_lookup[hashed]} : {pwd}")
            del hash_lookup[hashed]
        if not hash_lookup:
            print("\n[✔] All hashes cracked.")
            break

if hash_lookup:
    print(f"\n[-] Still uncracked: {len(hash_lookup)}")

