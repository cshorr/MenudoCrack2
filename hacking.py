import hashlib

# Hashes to crack
target_hashes = {
    "cac9e1f4e1664ffabc3a9958bd5eb7b4": None,
    "fa1fc88ed2bcffa3a2c9721738d5dd82": None,
    "a6c8f8fe09042f4ab28d0048575cd9d4": None,
}

# Path to rockyou wordlist
wordlist_path = "P:/Hacking.py_Wordlist/rockyou.txt"


# Open and loop through the wordlist
with open(wordlist_path, "r", encoding="latin-1") as file:
    for line in file:
        word = line.strip()
        hash = hashlib.md5(word.encode()).hexdigest()
        if hash in target_hashes and target_hashes[hash] is None:
            target_hashes[hash] = word
            print(f"✅ Found: {hash} = {word}")
        if all(target_hashes.values()):
            break

# Show any that weren’t cracked
for h, pw in target_hashes.items():
    if pw:
        print(f"{h} => {pw}")
    else:
        print(f"{h} => ❌ Not found")
