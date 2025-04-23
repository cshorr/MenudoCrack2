#!/usr/bin/env python3

import subprocess
import os
from pathlib import Path

# === Step 1: Get the hash ===
hash_input = input("Enter the hash to crack: ").strip()
hash_file = Path.home() / "PythonProjects" / "NCL_Tools" / "Hacking.py" / "hashes.txt"

# Save hash to file
with open(hash_file, "w") as f:
    f.write(hash_input + "\n")

# === Step 2: Wordlists ===
wordlist_folder = Path.home() / "PythonProjects" / "NCL_Tools" / "Hacking.py"
wordlists = [
    "pokemon.txt",
    "wordlists/custom_wordlist.txt",
    "wordlists/rockyou_large/rockyou.txt",
    "wordlists/SecLists/Passwords/darkc0de.txt",
    "wordlists/SecLists/Passwords/500-worst-passwords.txt",
    "wordlists/SecLists/Passwords/darkweb2017-top10000.txt"
]

# === Step 3: Hashcat settings ===
hashcat_path = "hashcat"  # Assumes hashcat is installed and in PATH (via apt or extracted)
hash_mode = "0"  # MD5; you can change this per hash type
base_dir = wordlist_folder  # cwd for hashcat, same as wordlist dir

print("\n🔥 Starting Hashcat Beastmode...\n")

# === Step 4: Try each wordlist ===
for wl in wordlists:
    wordlist_path = wordlist_folder / wl
    if not wordlist_path.exists():
        print(f"[!] Wordlist not found: {wordlist_path}")
        continue

    print(f"\n[*] Trying wordlist: {wordlist_path.name}")

    hashcat_cmd = [
        hashcat_path, "-m", hash_mode, "-a", "0",
        str(hash_file), str(wordlist_path),
        "--gpu-temp-abort=85", "--status", "--status-timer=15", "--force"
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
        if password_line:
            cracked = password_line.split(":")[-1]
            print(f"\n[✔] Password Found: {cracked}\n")
        else:
            print("[❌] Hash recovered, but password extraction failed.")
        break

print("\n[🏁] All wordlists processed.")
