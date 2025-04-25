#!/usr/bin/env python3

import subprocess
import json
from pathlib import Path

config_path = Path.home() / "PythonProjects" / "NCL_Tools" / "Hacking.py" / "wordlist_paths.json"
with open(config_path) as f:
    wordlists = json.load(f)

hash_input = input("Enter the hash to crack: ").strip()
hash_file = Path.home() / "PythonProjects" / "NCL_Tools" / "Hacking.py" / "hashes.txt"

with open(hash_file, "w") as f:
    f.write(hash_input + "\n")

hashcat_path = "hashcat"
hash_mode = "0"
base_dir = Path.home() / "PythonProjects" / "NCL_Tools" / "Hacking.py"

print("\n🔥 DEBUG MODE: Running Hashcat\n")

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

    print("Command:", " ".join(hashcat_cmd))
    result = subprocess.run(
        hashcat_cmd,
        cwd=str(base_dir),
        capture_output=True,
        text=True
    )

    print("STDOUT:\n", result.stdout)
    print("STDERR:\n", result.stderr)

    show_cmd = [
        hashcat_path, "-m", hash_mode, "--show", str(hash_file)
    ]
    show_result = subprocess.run(
        show_cmd,
        cwd=str(base_dir),
        capture_output=True,
        text=True
    )

    print("SHOW OUTPUT:\n", show_result.stdout)

    if ":" in show_result.stdout:
        cracked = show_result.stdout.split(":", 1)[1].strip()
        print(f"\n✅ SUCCESS: Password is: {cracked}")
        break
else:
    print("\n❌ Nothing cracked in any wordlist.")
