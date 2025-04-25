#!/usr/bin/env python3

import subprocess
import json
from pathlib import Path
import os

# === Load wordlists from config ===
config_path = Path.home() / "PythonProjects" / "NCL_Tools" / "Hacking.py" / "wordlist_paths.json"
with open(config_path) as f:
    wordlists = json.load(f)

# === Step 1: Get the hash ===
hash_input = input("Enter the hash to crack: ").strip()
hash_file = Path.home() / "PythonProjects" / "NCL_Tools" / "Hacking.py" / "hashes.txt"

# Save hash to file
with open(hash_file, "w") as f:
    f.write(hash_input + "\n")

# === Step 2: Hashcat settings ===
hashcat_path = "/usr/bin/hashcat"
hash_mode = "0"  # MD5
base_dir = Path.home() / "PythonProjects" / "NCL_Tools" / "Hacking.py"

print("\n🔥 Starting Hashcat Beastmode...\n")

# === Step 3: Try each wordlist ===
for name, path in wordlists.items():
    wordlist_path = Path(path)
    if not wordlist_path.exists():
        print(f"[!] Wordlist not found: {wordlist_path}")
        continue

    print(f"\n[*] Trying wordlist: {name}")

    hashcat_cmd = [
        hashcat_path, "-m", hash_mode, "-a", "0",
        str(hash_file), str(wordlist_path),
        "--force"
    ]

    print("Running:", " ".join(hashcat_cmd))

    result = subprocess.run(
        hashcat_cmd,
        cwd=str(base_dir),
        capture_output=True,
        text=True
    )

    if "Recovered" in result.stdout or "Recovered" in result.stderr:
        print("\n[✔] Hash Recovered! Checking result...\n")

        show_cmd = [
            hashcat_path, "-m", hash_mode, "--show", str(hash_file)
        ]
        show_result = subprocess.run(
            show_cmd,
            cwd=str(base_dir),
            capture_output=True,
            text=True
        )
        print("RAW --show OUTPUT:\n", show_result.stdout)

        password_lines = show_result.stdout.strip().splitlines()
        found = False

        for line in password_lines:
            if ":" in line:
                hash_value, cracked = line.split(":", 1)
                print(f"\n✅ Success 😄 Password: {cracked.strip()}\n")
                found = True
                break

        if not found:
            print("[❌] Hash recovered, but password extraction failed.")

            # Fallback: read from potfile
            potfile_path = os.path.expanduser("~/.hashcat/hashcat.potfile")
            if os.path.exists(potfile_path):
                with open(potfile_path, "r") as pot:
                    for pot_line in pot:
                        if hash_input in pot_line:
                            cracked = pot_line.strip().split(":", 1)[1]
                            print(f"\n✅ SUCCESS (from potfile): {cracked}")
                            break
            else:
                print("[⚠️] Potfile not found. Hashcat may not have logged the result.")

        break
else:
    print("\n😵 Password not found in any wordlist.\n")

print("\n[🏁] All wordlists processed.")



# 68a96446a5afb4ab69a2d15091771e39
# ec5f0b1826389df8622133014e88afde
# 32e5f63b189b78dccf0b97ac41f0d228
# 2233287f476ba63323e60addca1f6b64
#
# 6539bbb84fe2de2628fc5e4f2a31f23a