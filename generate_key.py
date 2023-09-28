import bcrypt
from cryptography.fernet import Fernet


def hashed_password():
    # your password
    password = "your-password"
    bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(bytes, salt)

    print(hash)


def encryption_key():
    # Generate a new encryption key
    encryption_key = Fernet.generate_key()
    print(encryption_key.decode())


if __name__ == "__main__":
    hashed_password()
    encryption_key()
