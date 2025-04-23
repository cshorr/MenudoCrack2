def vigenere_sq(alphabet):
    print(f"|   | {' | '.join(alphabet)} |")
    print("|---|---" * (len(alphabet) + 1))
    for i, letter in enumerate(alphabet):
        row = [alphabet[(i + j) % len(alphabet)] for j in range(len(alphabet))]
        print(f"| {letter} | {' | '.join(row)} |")

def letter_to_index(letter, alphabet):
    return alphabet.index(letter)

def index_to_letter(index, alphabet):
    return alphabet[index]

def vigenere_index(key_letter, plaintext_letter, alphabet):
    key_index = letter_to_index(key_letter, alphabet)
    plaintext_index = letter_to_index(plaintext_letter, alphabet)
    return index_to_letter((key_index + plaintext_index) % len(alphabet), alphabet)

def encrypt_vigenere(key, plaintext, alphabet):
    key_index = 0
    ciphertext = ""
    for plaintext_letter in plaintext:
        if plaintext_letter in alphabet:
            key_letter = key[key_index % len(key)]
            ciphertext += vigenere_index(key_letter, plaintext_letter, alphabet)
            key_index += 1
        else:
            ciphertext += plaintext_letter  # preserve non-alphabet characters
    return ciphertext

def undo_vigenere_index(key_letter, cipher_letter, alphabet):
    key_index = letter_to_index(key_letter, alphabet)
    cipher_index = letter_to_index(cipher_letter, alphabet)
    return index_to_letter((cipher_index - key_index) % len(alphabet), alphabet)

def decrypt_vigenere(key, cipher_text, alphabet):
    key_index = 0
    plaintext = ""
    for cipher_letter in cipher_text:
        if cipher_letter in alphabet:
            key_letter = key[key_index % len(key)]
            plaintext += undo_vigenere_index(key_letter, cipher_letter, alphabet)
            key_index += 1
        else:
            plaintext += cipher_letter  # preserve non-alphabet characters
    return plaintext

def main():
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    while True:
        print("1. Encrypt")
        print("2. Decrypt")
        choice = input("Enter your choice: ")
        if choice == "1":
            plaintext = input("Enter plaintext: ").upper()
            key = input("Enter key: ").upper()
            ciphertext = encrypt_vigenere(key, plaintext, alphabet)
            print("Ciphertext:", ciphertext)
        elif choice == "2":
            cipher_text = input("Enter ciphertext: ").upper()
            key = input("Enter key: ").upper()
            plaintext = decrypt_vigenere(key, cipher_text, alphabet)
            print("Plaintext:", plaintext)
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
