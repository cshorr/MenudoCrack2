
import hashlib
import os

# Ask for hash
target_hash = input("Enter the MD5 hash to crack: ").strip()

# Wordlist path (UPDATE THIS if needed)
pokemon_wordlist = "/home/cshor/PythonProjects/NCL_Tools/Hacking.py/wordlists/pokemon.txt"

# Check if file exists
if not os.path.isfile(pokemon_wordlist):
    print(f"[ERROR] Wordlist not found at {pokemon_wordlist}")
    exit(1)

# Load wordlist
with open(pokemon_wordlist, "r", encoding="utf-8") as file:
    pokemon_names = [line.strip() for line in file if line.strip()]

# Compare hashes
for name in pokemon_names:
    if hashlib.md5(name.encode()).hexdigest() == target_hash:
        print(f"\n[✔] Match found! The password is: {name}")
        break
else:
    print("\n[✖] No match found.")

#   5f0f88c7b6c72c44f69c4ee6f8a55daa
