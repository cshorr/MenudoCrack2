import hashlib
import itertools
import string
import multiprocessing
from tqdm import tqdm
import signal
import time
import os

# ---------------------
# CONFIGURATION
# ---------------------

STATIC_WORD = "liber8"
SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:,.<>?/~`"
HASH_FILE = r"P:\Hacking.py_Wordlist\Hashes.txt"
WORDLIST = r"P:\Hacking.py_Wordlist\rockyou.txt"
MAX_WORDS = None  # Adjust as needed
NUM_WORKERS = 4   # Set the number of worker processes (e.g., 4)

# ---------------------
# LOADERS
# ---------------------

def load_hashes():
    with open(HASH_FILE, 'r') as f:
        return [line.strip() for line in f if ':' not in line]

def load_words(limit=None):
    with open(WORDLIST, 'r', encoding='utf-8', errors='ignore') as f:
        words = [line.strip() for line in f if line.strip().isalpha()]
    return words[:limit] if limit else words

# ---------------------
# CANDIDATE GENERATOR
# ---------------------

def generate_candidates(word1, word2):
    variants = []

    # Type 1: all lowercase, "-" separator
    variants.append(f"{word1}-{word2}-{STATIC_WORD}")

    # Type 2: any special char, all lowercase
    for sep in SPECIAL_CHARS:
        variants.append(f"{word1}{sep}{word2}{sep}{STATIC_WORD}")

    # Type 3: upper/lower variations
    for sep in SPECIAL_CHARS:
        variants.append(f"{word1.upper()}{sep}{word2.upper()}{sep}{STATIC_WORD}")
        variants.append(f"{word1.lower()}{sep}{word2.upper()}{sep}{STATIC_WORD}")
        variants.append(f"{word1.upper()}{sep}{word2.lower()}{sep}{STATIC_WORD}")

    # Type 4: digit added to one word
    for sep in SPECIAL_CHARS:
        for d in string.digits:
            variants.append(f"{word1}{d}{sep}{word2}{sep}{STATIC_WORD}")
            variants.append(f"{word1}{sep}{word2}{d}{sep}{STATIC_WORD}")
    return variants

# ---------------------
# HASH CHECKING
# ---------------------

def hash_sha1(text):
    return hashlib.sha1(text.encode()).hexdigest()

def crack_chunk(chunk, all_words, target_hashes):
    found = {}
    for word1 in tqdm(chunk, desc=f"PID {os.getpid()}", position=0, leave=True):
        for word2 in all_words:
            for candidate in generate_candidates(word1, word2):
                h = hash_sha1(candidate)
                if h in target_hashes:
                    found[h] = candidate
    return found

# ---------------------
# MAIN EXECUTION
# ---------------------

def crack_hashes():
    hashes = load_hashes()
    words = load_words(MAX_WORDS)
    cpu_cores = NUM_WORKERS
    chunks = [words[i::cpu_cores] for i in range(cpu_cores)]

    args = [(chunk, words, hashes) for chunk in chunks]

    print(f"[~] Cracking with {cpu_cores} cores using {len(words)} words against {len(hashes)} hashes...")

    with multiprocessing.Pool(cpu_cores) as pool:
        results = pool.starmap(crack_chunk, args)

    cracked = {}
    for r in results:
        cracked.update(r)

    with open("cracked_output.txt", "w") as out:
        for h, plain in cracked.items():
            out.write(f"{h}:{plain}\n")

    print(f"[+] Cracked {len(cracked)} of {len(hashes)} hashes.")
    return cracked

# ---------------------
# GO TIME
# ---------------------

if __name__ == "__main__":
    multiprocessing.set_start_method('spawn')
    crack_hashes()
