import hashlib

plaintext = input("Enter a word to hash (MD5): ").strip()
hashed = hashlib.md5(plaintext.encode()).hexdigest()

print(f"MD5 hash: {hashed}")




# Enter a word to hash (MD5): superman
# MD5 hash: 84d961568a65073a3bcf0eb216b2a576