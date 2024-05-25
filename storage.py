from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import os
import json

class PasswordManager:
    def __init__(self, key):
        self.key = key
        self.entries = {}

    def encrypt_password(self, password):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(password.encode()) + padder.finalize()
        
        encrypted_password = encryptor.update(padded_data) + encryptor.finalize()
        return b64encode(iv + encrypted_password).decode()

    def decrypt_password(self, encrypted_password):
        encrypted_data = b64decode(encrypted_password)
        iv = encrypted_data[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_padded_password = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
        
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        password = unpadder.update(decrypted_padded_password) + unpadder.finalize()
        return password.decode()

    def add_password(self, name, password):
        self.entries[name] = self.encrypt_password(password)

    def get_password(self, name):
        if name in self.entries:
            return self.decrypt_password(self.entries[name])
        return None

    def save_to_file(self, filename):
        with open(filename, 'w') as f:
            json.dump(self.entries, f)

    def load_from_file(self, filename):
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                self.entries = json.load(f)

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())
