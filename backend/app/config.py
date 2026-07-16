import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "CloudSentinel"
    API_V1_STR: str = "/api"
    
    # JWT Auth settings
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-key-change-in-production-1234567890")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    
    # Database settings
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./cloudsentinel.db")
    
    # Encryption key for AWS Credentials (stored in DB)
    ENCRYPTION_KEY: str = os.getenv("ENCRYPTION_KEY", "z2WfS6-2L1aHk_Q28tI5SjY3P4Xm_oN5M1L2k3J4I5o=")

    class Config:
        case_sensitive = True

settings = Settings()
