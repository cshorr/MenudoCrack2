from passlib.hash import nthash

# Hashes to crack (NTLM)
target_hashes = {
    "74A942B14C50D4ED03D9A4CC8866199C": None,
    "00C5EDFB2451217802FFDE8B8E941D13": None,
    "D8803339BE9876BBE3DAFF80CC27D271": None
}

wordlist_path = "P:/Hacking.py_Wordlist/rockyou.txt"

with open(wordlist_path, "r", encoding="latin-1") as file:
    for line in file:
        word = line.strip()
        h = nthash.hash(word).upper()
        if h in target_hashes and target_hashes[h] is None:
            target_hashes[h] = word
            print(f"✅ Found: {h} = {word}")
        if all(target_hashes.values()):
            break

print("\n--- Final Cracked Hashes ---")
for h, pw in target_hashes.items():
    if pw:
        print(f"{h} => {pw}")
    else:
        print(f"{h} => ❌ Not found")
