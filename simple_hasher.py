import hashlib

def hash_passwords(password):
    print(f"\nHashing password: {password}\n")
    print("MD5:     ", hashlib.md5(password.encode()).hexdigest())
    print("SHA1:    ", hashlib.sha1(password.encode()).hexdigest())
    print("SHA256:  ", hashlib.sha256(password.encode()).hexdigest())

if __name__ == "__main__":
    pwd = input("Enter password: ").strip()
    hash_passwords(pwd)
