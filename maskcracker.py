import crypt
import itertools
import string

# Target hashes
targets = {
    "$1$MASK$cAibbcHrPXJfQQJnsxKKN/": None,
    "$1$MASK$oxLb/Rd5/hF4/Wplvkvw6/": None,
    "$1$MASK$vP1R7sPWuKv29Yxub2kws/": None
}

charset = string.ascii_lowercase + string.digits

for combo in itertools.product(charset, repeat=4):
    suffix = ''.join(combo)
    candidate = f"SKY-MASK-{suffix}"
    hashed = crypt.crypt(candidate, "$1$MASK$")

    if hashed in targets and targets[hashed] is None:
        targets[hashed] = candidate
        print(f"✅ Found: {hashed} = {candidate}")

    if all(targets.values()):
        break

# Final summary
print("\n🧾 Final Results:")
for h, pw in targets.items():
    print(f"{h} => {pw if pw else '❌ Not found'}")
