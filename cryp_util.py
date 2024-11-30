# crypto_utils.py
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import hashlib
import hmac

class CryptoUtils:
    @staticmethod
    def derive_key(shared_secret: bytes, salt: bytes) -> bytes:
        """Derive a key from the shared secret using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(shared_secret))
        return key

    @staticmethod
    def encrypt_message(key: bytes, message: str) -> tuple[bytes, bytes]:
        """Encrypt a message using Fernet (AES)."""
        f = Fernet(key)
        message_bytes = message.encode()
        encrypted_message = f.encrypt(message_bytes)
        # Create MAC for integrity
        mac = hmac.new(key, encrypted_message, hashlib.sha256).digest()
        return encrypted_message, mac

    @staticmethod
    def decrypt_message(key: bytes, encrypted_message: bytes, mac: bytes) -> str:
        """Decrypt a message using Fernet (AES)."""
        # Verify MAC first
        expected_mac = hmac.new(key, encrypted_message, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("Message authentication failed")
        
        f = Fernet(key)
        decrypted_message = f.decrypt(encrypted_message)
        return decrypted_message.decode()


