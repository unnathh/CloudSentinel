from cryptography.fernet import Fernet
from app.config import settings

class EncryptionService:
    def __init__(self):
        # The key must be a 32-byte URL-safe base64 key
        self.fernet = Fernet(settings.ENCRYPTION_KEY.encode())

    def encrypt(self, plain_text: str) -> str:
        if not plain_text:
            return ""
        return self.fernet.encrypt(plain_text.encode()).decode()

    def decrypt(self, cipher_text: str) -> str:
        if not cipher_text:
            return ""
        try:
            return self.fernet.decrypt(cipher_text.encode()).decode()
        except Exception:
            # If decryption fails (e.g. key mismatch), return empty
            return ""

encryption_service = EncryptionService()
