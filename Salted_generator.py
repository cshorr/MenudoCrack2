import hashlib
import bcrypt
import secrets

def generate_salted_hash(word, salt, algorithm):
    if algorithm in ['md5', 'sha1', 'sha256', 'sha512', 'blake2b']:
        # Concatenate the salt with the word
        word_to_hash = (salt + word) if salt else word
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(word_to_hash.encode('utf-8'))
        return hash_obj.hexdigest()
    elif algorithm == 'bcrypt':
        # For bcrypt, if a valid salt is provided it must start with "$2b$".
        if salt:
            try:
                salt_bytes = salt.encode('utf-8')
                if not salt_bytes.startswith(b'$2b$'):
                    raise ValueError("Invalid bcrypt salt format. It should start with '$2b$'.")
                hashed = bcrypt.hashpw(word.encode('utf-8'), salt_bytes)
            except Exception as e:
                print("Error using provided salt for bcrypt:", e)
                print("Generating new salt instead.")
                hashed = bcrypt.hashpw(word.encode('utf-8'), bcrypt.gensalt())
        else:
            hashed = bcrypt.hashpw(word.encode('utf-8'), bcrypt.gensalt())
        return hashed.decode('utf-8')
    else:
        return None

def main():
    print("=== Salted Hash Generator ===")
    word = input("Enter the word to hash: ")

    # Ask whether to generate a random salt or input a custom one.
    generate_random = input("Generate a random salt? (Y/n): ").strip().lower()
    if generate_random in ['y', 'yes', '']:
        salt = secrets.token_hex(16)  # Generates a 32-character hexadecimal salt.
        print("Generated random salt:", salt)
    else:
        salt = input("Enter your custom salt: ")

    print("\nSelect hash algorithm:")
    print("[1] MD5")
    print("[2] SHA1")
    print("[3] SHA256")
    print("[4] SHA512")
    print("[5] BLAKE2b")
    print("[6] Bcrypt")

    choice = input("Enter your choice: ")
    alg_map = {
        "1": "md5",
        "2": "sha1",
        "3": "sha256",
        "4": "sha512",
        "5": "blake2b",
        "6": "bcrypt"
    }
    algorithm = alg_map.get(choice)
    if not algorithm:
        print("Invalid choice.")
        return

    result = generate_salted_hash(word, salt, algorithm)
    print("\nSalted Hash:", result)

if __name__ == "__main__":
    main()
