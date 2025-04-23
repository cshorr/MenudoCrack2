from cryptography.fernet import Fernet

def encrypt_data(data, key):
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data

*/import subprocess
*/
# Step 1: Get the hash from user input
hash_input = input("Enter the hash to crack: ").strip()

# Step 2: Save the hash to a file (this will be used by Hashcat)
hash_file = "P:/Hacking.py/hashes.txt"
with open(hash_file, "w") as f:
    f.write(hash_input)

# Step 3: Define the list of wordlists
wordlist_folder = "P:/Hacking.py_Wordlist/"  # Main wordlist folder
wordlists = [
    "rockyou_large/rockyou.txt",  # RockYou wordlist
    "SecLists/Passwords/darkc0de.txt",  # Common hacker passwords
    "SecLists/Passwords/500-worst-passwords.txt",  # Weakest passwords
    "SecLists/Passwords/darkweb2017-top10000.txt",  # Real-world leaked passwords
    #f71dbe52628a3f83a77ab494817525c6
    "pokemon.txt"  # Your Pokémon wordlist
]

# Path to Hashcat executable
hashcat_path = r"P:\Hacking.Py_Hashcat\hashcat-6.2.6\hashcat.exe"

# Step 4: Loop through each wordlist and try cracking the hash
for wordlist in wordlists:
    wordlist_path = wordlist_folder + wordlist
    print(f"\n[*] Trying wordlist: {wordlist_path}")

    # Create the Hashcat command
    hashcat_cmd = [
        hashcat_path, "-m", "0", "-a", "0", hash_file, wordlist_path,
        "--force", "--backend-ignore-opencl", "--self-test-disable"
    ]

    # Step 5: Run Hashcat with the current wordlist
    result = subprocess.run(
        hashcat_cmd,
        cwd=r"P:\Hacking.Py_Hashcat\hashcat-6.2.6",
        capture_output=True,
        text=True
    )

    # Step 6: Print the output from Hashcat
    print("\nHashcat Output:")
    print(result.stdout)
    print(result.stderr)

    # Check if Hashcat found a password
    if "Recovered" in result.stdout:
        print("\n[✔] Password found! Stopping...")
        break  # Stop looping if a password was found

print("\n[!] All wordlists attempted.")
