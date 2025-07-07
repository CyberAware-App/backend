from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from datetime import timedelta

from db import models, schemas, database
from core import security
from core import email
from utils.response import ResponseMixin

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

@router.post("/register")
async def register(request: schemas.UserCreate, db: Session = Depends(database.get_db)):
    """Register a new user"""
    
    db_user = db.query(models.User).filter(models.User.email == request.email).first()
    if db_user:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ResponseMixin.error_response(errors={"email": "Email already exists"}, message="Registration failed")
        )
    
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
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ResponseMixin.error_response(errors={"email": "Failed to send verification email. Please try again."}, message="Registration failed")
        )
        
    user_data = {
        "id": new_user.id,
        "email": new_user.email,
        "first_name": new_user.first_name,
        "last_name": new_user.last_name,
        "is_verified": new_user.is_verified
    }
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=ResponseMixin.success_response(data=user_data, message="User registered successfully")
    )


@router.post("/verify-email")
def verify_email(request: schemas.OTPVerify, db: Session = Depends(database.get_db)):
    """Verify user email with OTP code"""
    
    if not email.verify_otp(db, request.email, request.otp_code):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ResponseMixin.error_response(errors={"otp_code": "Invalid or expired OTP code"}, message="Verification failed")
        )
    
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if not user:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ResponseMixin.error_response(errors={"email": "User not found"}, message="Verification failed")
        )
    user.is_verified = True
    db.commit()
    
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=ResponseMixin.success_response(data={"email": request.email}, message="Email verified successfully")
    )


@router.post("/resend-otp")
async def resend_otp(email_address: str, db: Session = Depends(database.get_db)):
    """Resend OTP verification email"""
    
    user = db.query(models.User).filter(models.User.email == email_address).first()
    if not user:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ResponseMixin.error_response(errors={"email": "User not found"}, message="Resend OTP failed")
        )
    if user.is_verified:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ResponseMixin.error_response(errors={"email": "User is already verified"}, message="Resend OTP failed")
        )
    
    try:
        otp_record = email.create_otp_record(db, user.id)
        await email.send_otp_email(email_address, otp_record.code)
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ResponseMixin.error_response(errors={"email": "Failed to send verification email. Please try again."}, message="Resend OTP failed")
        )
    
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=ResponseMixin.success_response(data={"email": email_address}, message="OTP sent successfully")
    )


@router.post("/forgot-password")
async def forgot_password(request: schemas.ForgotPasswordRequest, db: Session = Depends(database.get_db)):
    """Send password reset OTP email"""
    
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if not user:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=ResponseMixin.success_response(data={"email": request.email}, message="If the email exists, a password reset code has been sent")
        )
    
    if not user.is_verified:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ResponseMixin.error_response(errors={"email": "Please verify your email first before resetting password"}, message="Forgot password failed")
        )
    
    try:
        otp_record = email.create_otp_record(db, user.id)
        await email.send_password_reset_email(request.email, otp_record.code)
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ResponseMixin.error_response(errors={"email": "Failed to send password reset email. Please try again."}, message="Forgot password failed")
        )
    
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=ResponseMixin.success_response(data={"email": request.email}, message="Password reset code sent successfully")
    )


@router.post("/reset-password")
def reset_password(request: schemas.ResetPasswordRequest, db: Session = Depends(database.get_db)):
    """Reset password using OTP code"""
    
    if not email.verify_otp(db, request.email, request.otp_code):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ResponseMixin.error_response(errors={"otp_code": "Invalid or expired OTP code"}, message="Reset password failed")
        )
    
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if not user:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ResponseMixin.error_response(errors={"email": "User not found"}, message="Reset password failed")
        )
    
    if not user.is_verified:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ResponseMixin.error_response(errors={"email": "Please verify your email first"}, message="Reset password failed")
        )
    
    user.hashed_password = security.get_password_hash(request.new_password)
    db.commit()
    
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=ResponseMixin.success_response(data={"email": request.email}, message="Password reset successfully")
    )


@router.post("/change-password")
async def change_password(
    request: schemas.ChangePasswordRequest, 
    current_user: models.User = Depends(security.get_current_active_user),
    db: Session = Depends(database.get_db)
):
    """Change password for authenticated user"""
    
    if not security.verify_password(request.current_password, current_user.hashed_password):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ResponseMixin.error_response(errors={"current_password": "Current password is incorrect"}, message="Change password failed")
        )
    
    current_user.hashed_password = security.get_password_hash(request.new_password)
    db.commit()
    
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=ResponseMixin.success_response(data={"email": current_user.email}, message="Password changed successfully")
    )


@router.post("/login")
async def login(request: schemas.UserLogin, db: Session = Depends(database.get_db)):
    """Login with email and password"""
    
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if not user or not security.verify_password(request.password, user.hashed_password):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=ResponseMixin.error_response(errors={"credentials": "Invalid credentials"}, message="Login failed")
        )
    
    if not user.is_verified:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ResponseMixin.error_response(errors={"email": "Please verify your email before logging in"}, message="Login failed")
        )
    
    access_token_expires = timedelta(minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires
    )
    token_data = {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id
    }
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=ResponseMixin.success_response(data=token_data, message="Login successful")
    )

