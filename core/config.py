import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    SECRET_KEY: str = os.getenv("SECRET_KEY")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 4320 # 3 days
    SENDGRID_API_KEY: str = os.getenv("SENDGRID_API_KEY")
    MAIL_FROM: str = os.getenv("MAIL_FROM")
    OTP_EXPIRE_MINUTES: int = 10

settings = Settings()