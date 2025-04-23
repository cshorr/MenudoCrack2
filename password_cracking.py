import hashlib
import itertools
import random

# Import the wordlists
rockyou_wordlist = open('\\wsl$\\Ubuntu\\home\\cshor\\hacking\\rockyou.txt', 'r').readlines()
pokemon_wordlist = open('\\wsl$\\Ubuntu\\home\\cshor\\hacking\\pokemon.txt', 'r').readlines()
seclists_wordlist = open('\\wsl$\\Ubuntu\\home\\cshor\\hacking\\SecLists\\wordlists.txt', 'r').readlines()

def crack_password(hash_value, wordlist):
    for word in wordlist:
        hashed_word = hashlib.sha256(word.strip().encode()).hexdigest()
        if hashed_word == hash_value:
            return word.strip()
    return None

# Generate some random hashes for testing
def generate_random_hash(wordlist):
    word = random.choice(wordlist)
    return hashlib.sha256(word.strip().encode()).hexdigest()

# Example usage
hash_values = [
    generate_random_hash(rockyou_wordlist),
    generate_random_hash(pokemon_wordlist),
    generate_random_hash(seclists_wordlist)
]

for hash_value in hash_values:
    print(f"Cracking hash: {hash_value}")
    cracked_password = crack_password(hash_value, rockyou_wordlist)
    if cracked_password:
        print(f"Cracked password: {cracked_password}")
    else:
        print("Password not found in wordlist")
    print()