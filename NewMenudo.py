import hashlib
import bcrypt
import logging
import itertools
import string
from passlib.hash import md5_crypt

# ---------------------
# Configuration Options
# ---------------------

WORDLISTS = [
    r"P:\Hacking.py_Wordlist\rockyou.txt",
    r"P:\Hacking.py_P\wordlists\common.txt",
    r"P:\Hacking.py_P\wordlists\passwords.txt"
]

SALT_PLACEMENT = "prepend"

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ---------------------
# Cracking Functionality
# ---------------------

def crack_hash(hash_to_crack, hash_type, wordlist_path, salt=None):
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            counter = 0
            for word in file:
                counter += 1
                word = word.strip()
                if not word:
                    continue

                candidate = (salt + word) if salt and SALT_PLACEMENT == "prepend" else (word + salt if salt else word)

                try:
                    if hash_type == 'bcrypt':
                        if bcrypt.checkpw(word.encode('utf-8'), hash_to_crack.encode()):
                            logging.info(f"Match found for bcrypt after {counter} words")
                            return word
                    elif hash_type == 'md5-crypt':
                        if md5_crypt.verify(word, hash_to_crack):
                            logging.info(f"Match found for md5-crypt after {counter} words")
                            return word
                    else:
                        hashed_candidate = hashlib.new(hash_type, candidate.encode('utf-8')).hexdigest()
                        if hashed_candidate == hash_to_crack:
                            logging.info(f"Match found after {counter} words")
                            return word
                except Exception as e:
                    logging.error(f"Error testing word '{word}': {e}")
                    continue

                if counter % 10000 == 0:
                    logging.debug(f"Tested {counter} words in {wordlist_path}")

    except FileNotFoundError:
        logging.error(f"Wordlist file not found: {wordlist_path}")
    except Exception as e:
        logging.error(f"Error opening wordlist: {e}")
    return None

# ---------------------
# Special Brute Force for SKY-MASK-????
# ---------------------

def brute_sky_mask_md5crypt(target_hash, salt="MASK"):
    charset = string.ascii_uppercase + string.digits
    prefix = "SKY-MASK-"
    counter = 0

    print(f"\n[~] Starting brute force for {target_hash} ...")

    for combo in itertools.product(charset, repeat=4):
        guess = prefix + ''.join(combo)
        counter += 1
        try:
            if md5_crypt.verify(guess, target_hash):
                print(f"[+] Match found after {counter} attempts: {guess}")
                return guess
        except Exception:
            continue

        if counter % 10000 == 0:
            print(f"[-] Tested {counter} candidates...")

    print("[-] No match found in SKY-MASK-???? brute space.")
    return None

# ---------------------
# Main Menu & Input Handling
# ---------------------

def main():
    hash_types = {
        '1': 'md5',
        '1a': 'md5-crypt',
        '2': 'sha1',
        '3': 'sha256',
        '4': 'sha512',
        '5': 'blake2b',
        '6': 'bcrypt',
        '7': 'sky-mask-md5crypt'
    }

    while True:
        print("\n--- MenudoCrack v1.3 ---")
        print("[1] Crack MD5")
        print("[1a] Crack MD5-Crypt ($1$ style)")
        print("[2] Crack SHA1")
        print("[3] Crack SHA256")
        print("[4] Crack SHA512")
        print("[5] Crack BLAKE2b")
        print("[6] Crack Bcrypt")
        print("[7] Brute SKY-MASK-???? [MD5-crypt]")
        print("[0] Exit")

        choice = input("Enter your choice: ").strip()
        if choice == '0':
            print("Exiting MenudoCrack.")
            break
        if choice not in hash_types:
            print("Invalid choice.")
            continue

        hash_type = hash_types[choice]

        if hash_type == 'sky-mask-md5crypt':
            user_hash = input("Enter the full $1$salt$hash: ").strip()
            brute_sky_mask_md5crypt(user_hash)
            continue

        user_hash = input("Enter hash: ").strip()
        if not user_hash:
            print("Hash cannot be empty.")
            continue

        salt = None
        if hash_type not in ['bcrypt', 'md5-crypt']:
            if input("Is the hash salted? (y/n): ").strip().lower() == 'y':
                salt = input("Enter salt: ").strip()
                if not salt:
                    print("Salt required.")
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
