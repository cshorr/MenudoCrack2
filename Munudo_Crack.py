import hashlib
import bcrypt
import logging
from passlib.hash import md5_crypt

# ---------------------
# Configuration Options
# ---------------------

# List of wordlists to try
WORDLISTS = [
    r"P:\Hacking.py_Wordlist\rockyou.txt",
    r"P:\Hacking.py_P\wordlists\common.txt",
    r"P:\Hacking.py_P\wordlists\passwords.txt"
]

# How to combine salt and word: "prepend" or "append"
SALT_PLACEMENT = "prepend"  # change to "append" if desired

# Configure logging to output debug messages to console
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ---------------------
# Cracking Functionality
# ---------------------

def crack_hash(hash_to_crack, hash_type, wordlist_path, salt=None):
    """
    Attempt to crack a salted hash using the provided wordlist.
    The candidate word is normalized to lowercase before salting.
    The salt is combined with the candidate based on SALT_PLACEMENT.
    """
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            counter = 0
            for word in file:
                counter += 1
                word = word.strip().lower()  # Normalize candidate to lowercase
                if not word:
                    continue

                # Combine salt and candidate word in the chosen order.
                if salt:
                    candidate = (salt + word) if SALT_PLACEMENT == "prepend" else (word + salt)
                else:
                    candidate = word

                # For bcrypt, use checkpw directly
                if hash_type == 'bcrypt':
                    try:
                        if bcrypt.checkpw(word.encode('utf-8'), hash_to_crack.encode()):
                            logging.info(f"Match found for bcrypt after testing {counter} words")
                            return word
                    except Exception as e:
                        logging.error(f"Bcrypt error: {e}")
                        continue
                else:
                    try:
                        hashed_candidate = hashlib.new(hash_type, candidate.encode('utf-8')).hexdigest()
                    except Exception as e:
                        logging.error(f"Hashing error: {e}")
                        continue

                    if hashed_candidate == hash_to_crack:
                        logging.info(f"Match found after testing {counter} words")
                        return word

                # Provide progress feedback every 10,000 words
                if counter % 10000 == 0:
                    logging.debug(f"Tested {counter} words in {wordlist_path}")
            logging.debug(f"Finished processing {wordlist_path}, total words tested: {counter}")
    except FileNotFoundError:
        logging.error(f"Wordlist file not found: {wordlist_path}")
    except Exception as e:
        logging.error(f"Error processing wordlist {wordlist_path}: {e}")
    return None

# ---------------------
# Main Menu & Input Handling
# ---------------------

def main():
    hash_types = {
        '1': 'md5',
        '2': 'sha1',
        '3': 'sha256',
        '4': 'sha512',
        '5': 'blake2b',
        '6': 'bcrypt'
    }

    while True:
        print("\n--- MenudoCrack v1.1 ---")
        print("[1] Crack MD5")
        print("[2] Crack SHA1")
        print("[3] Crack SHA256")
        print("[4] Crack SHA512")
        print("[5] Crack BLAKE2b")
        print("[6] Crack Bcrypt")
        print("[0] Exit")

        choice = input("Enter your choice: ").strip()
        if choice == '0':
            print("Exiting MenudoCrack.")
            break
        if choice not in hash_types:
            print("Invalid choice, please select again.")
            continue

        hash_type = hash_types[choice]
        user_hash = input("Enter hash: ").strip()
        if not user_hash:
            print("No hash provided. Please try again.")
            continue

        salt = None
        if hash_type != 'bcrypt':
            salted = input("Is the hash salted? (y/n): ").strip().lower()
            if salted == 'y':
                salt = input("Enter the salt: ").strip()
                if not salt:
                    print("Salt cannot be empty if hash is salted. Please try again.")
                    continue

        found = False
        for wordlist in WORDLISTS:
            print(f"Trying wordlist: {wordlist}")
            result = crack_hash(user_hash, hash_type, wordlist, salt)
            if result:
                print(f"[+] Password Found: {result}")
                found = True
                break
        if not found:
            print("[-] Password not found in provided wordlists.")

if __name__ == "__main__":
    main()
# Example hashes for testing (plaintext: "superman")
# Hash Algorithm	Example Hash
# MD5	84d961568a65073a3bcf0eb216b2a576
# SHA1	0b1d5d8c9a7e1c18d8e31c02bd8a235a8388aeb9
# SHA256	d6b4a97e4221db26b9e27b01b30a85fc30508244371640cf36dc967c60fc8a78
# SHA512	6d94dcaa1ec02504e59f65812e1cb69961b60a1b79c7c742611ee5a3c4eb06b84634b74e282f66b9f3d0915bc978cb17c421e5f303b14a86246a
# NTLM	aad3b435b51404eeaad3b435b51404ee:c0ea4f2c00d2ce35d70e82972962a1dd
# BLAKE2b	57910f0b2238c65856170c7f5f60172816d8138f4da0a7c873fd5b8a77e0df99f2dd98eaf07977bcd1cb0a96e0b17aa661514da86f3f0c42ccf996ea3247b01
# Bcrypt	$2b$12$KIXJwxfFfclRAY9sh88j2uZQPt.kAGH7/b9bACrxJUOzZgnxPUE0S
#salted md5 hash=  b2320fc89d61f01b62f8d8e325a37f7e
#enter salt =  b32ca0042235423c7fda084057a5b6d0