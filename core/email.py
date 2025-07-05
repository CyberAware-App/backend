import random
import string
from datetime import datetime, timedelta
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from sqlalchemy.orm import Session
from core.config import settings
from db import models


def generate_otp() -> str:
    """Generate a 6-digit OTP code"""
    return ''.join(random.choices(string.digits, k=6))


def get_email_config():
    """Get email configuration based on provider"""
    return ConnectionConfig(
        MAIL_USERNAME="cyberaware-key",
        MAIL_PASSWORD=settings.SENDGRID_API_KEY,
        MAIL_FROM=settings.MAIL_FROM,
        MAIL_PORT=587,
        MAIL_SERVER="smtp.sendgrid.net",
        MAIL_TLS=True,
        MAIL_SSL=False,
        USE_CREDENTIALS=True
    )


async def send_otp_email(email: str, otp_code: str):
    """Send OTP verification email"""
    config = get_email_config()
    fm = FastMail(config)
    
    message = MessageSchema(
        subject="Email Verification - CyberAware",
        recipients=[email],
        body=f"""
        <html>
            <body>
                <h2>Email Verification</h2>
                <p>Your verification code is: <strong>{otp_code}</strong></p>
                <p>This code will expire in {settings.OTP_EXPIRE_MINUTES} minutes.</p>
                <p>If you didn't request this verification, please ignore this email.</p>
            </body>
        </html>
        """,
        subtype="html"
    )
    
    await fm.send_message(message)


async def send_password_reset_email(email: str, otp_code: str):
    """Send password reset OTP email"""
    config = get_email_config()
    fm = FastMail(config)
    
    message = MessageSchema(
        subject="Password Reset - CyberAware",
        recipients=[email],
        body=f"""
        <html>
            <body>
                <h2>Password Reset Request</h2>
                <p>You requested to reset your password.</p>
                <p>Your password reset code is: <strong>{otp_code}</strong></p>
                <p>This code will expire in {settings.OTP_EXPIRE_MINUTES} minutes.</p>
                <p>If you didn't request this password reset, please ignore this email and your password will remain unchanged.</p>
                <p><strong>Security Note:</strong> Never share this code with anyone.</p>
            </body>
        </html>
        """,
        subtype="html"
    )
    
    await fm.send_message(message)


def create_otp_record(db: Session, user_id: int) -> models.OTP:
    """Create and store OTP record in database"""
    db.query(models.OTP).filter(
        models.OTP.user_id == user_id,
        models.OTP.is_used == False
    ).delete()
    
    otp_code = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)
    
    otp_record = models.OTP(
        user_id=user_id,
        code=otp_code,
        expires_at=expires_at
    )
    db.add(otp_record)
    db.commit()
    db.refresh(otp_record)
    
    return otp_record


def verify_otp(db: Session, email: str, otp_code: str) -> bool:
    """Verify OTP code for a user"""
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        return False
    
    otp_record = db.query(models.OTP).filter(
        models.OTP.user_id == user.id,
        models.OTP.code == otp_code,
        models.OTP.is_used == False,
        models.OTP.expires_at > datetime.utcnow()
    ).first()
    
    if not otp_record:
        return False
    otp_record.is_used = True
    db.commit()
    
    return True 
