#!/usr/bin/env python3

import subprocess
import json
from pathlib import Path

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
hashcat_path = "hashcat"
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

        password_line = show_result.stdout.strip()
        if ":" in password_line:
            hash_value, cracked = password_line.split(":", 1)
            print(f"\n✅ Success 😄 Password: {cracked}\n")
        else:
            print("[❌] Hash recovered, but password extraction failed.")
        break
else:
    print("\n😵 Password not found in any wordlist.\n")

print("\n[🏁] All wordlists processed.")

