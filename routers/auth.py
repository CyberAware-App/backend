from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import timedelta

from db import models, schemas, database
from core import security
from core import email

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

@router.post("/register", response_model=schemas.UserResponse)
async def register(request: schemas.UserCreate, db: Session = Depends(database.get_db)):
    """Register a new user"""
    
    db_user = db.query(models.User).filter(models.User.email == request.email).first()
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists")
    
    new_user = models.User(
        email=request.email,
        first_name=request.first_name,
        last_name=request.last_name,
        hashed_password=security.get_password_hash(request.password),
        is_verified=False
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    try:
        otp_record = email.create_otp_record(db, new_user.id)
        await email.send_otp_email(request.email, otp_record.code)
    except Exception as e:
        # Clean up OTP record and user if email sending fails
        db.query(models.OTP).filter(models.OTP.user_id == new_user.id).delete()
        db.delete(new_user)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Failed to send verification email. Please try again."
        )
        
    return new_user


@router.post("/verify-email", response_model=schemas.OTPResponse)
def verify_email(request: schemas.OTPVerify, db: Session = Depends(database.get_db)):
    """Verify user email with OTP code"""
    
    if not email.verify_otp(db, request.email, request.otp_code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Invalid or expired OTP code"
        )
    
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="User not found"
        )
    user.is_verified = True
    db.commit()
    
    return schemas.OTPResponse(
        message="Email verified successfully",
        email=request.email
    )


@router.post("/resend-otp", response_model=schemas.OTPResponse)
async def resend_otp(email_address: str, db: Session = Depends(database.get_db)):
    """Resend OTP verification email"""
    
    user = db.query(models.User).filter(models.User.email == email_address).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="User not found"
        )
    if user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="User is already verified"
        )
    
    try:
        otp_record = email.create_otp_record(db, user.id)
        await email.send_otp_email(email_address, otp_record.code)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Failed to send verification email. Please try again."
        )
    
    return schemas.OTPResponse(
        message="OTP sent successfully",
        email=email_address
    )


@router.post("/forgot-password", response_model=schemas.OTPResponse)
async def forgot_password(request: schemas.ForgotPasswordRequest, db: Session = Depends(database.get_db)):
    """Send password reset OTP email"""
    
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if not user:
        return schemas.OTPResponse(
            message="If the email exists, a password reset code has been sent",
            email=request.email
        )
    
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Please verify your email first before resetting password"
        )
    
    try:
        otp_record = email.create_otp_record(db, user.id)
        await email.send_password_reset_email(request.email, otp_record.code)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Failed to send password reset email. Please try again."
        )
    
    return schemas.OTPResponse(
        message="Password reset code sent successfully",
        email=request.email
    )


@router.post("/reset-password", response_model=schemas.PasswordResponse)
def reset_password(request: schemas.ResetPasswordRequest, db: Session = Depends(database.get_db)):
    """Reset password using OTP code"""
    
    if not email.verify_otp(db, request.email, request.otp_code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Invalid or expired OTP code"
        )
    
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="User not found"
        )
    
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Please verify your email first"
        )
    
    user.hashed_password = security.get_password_hash(request.new_password)
    db.commit()
    
    return schemas.PasswordResponse(
        message="Password reset successfully"
    )


@router.post("/change-password", response_model=schemas.PasswordResponse)
async def change_password(
    request: schemas.ChangePasswordRequest, 
    current_user: models.User = Depends(security.get_current_active_user),
    db: Session = Depends(database.get_db)
):
    """Change password for authenticated user"""
    
    if not security.verify_password(request.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Current password is incorrect"
        )
    
    current_user.hashed_password = security.get_password_hash(request.new_password)
    db.commit()
    
    return schemas.PasswordResponse(
        message="Password changed successfully"
    )


@router.post("/login", response_model=schemas.Token)
async def login(request: schemas.UserLogin, db: Session = Depends(database.get_db)):
    """Login with email and password"""
    
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if not user or not security.verify_password(request.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please verify your email before logging in"
        )
    
    access_token_expires = timedelta(minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id
    }

