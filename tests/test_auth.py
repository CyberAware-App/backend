#!/usr/bin/env python3
"""
Test file for auth router endpoints
Tests all authentication functionality including registration, verification, login, and password management
"""

import pytest
import asyncio
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from unittest.mock import patch, MagicMock
import os
import sys

# Add the parent directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from db.database import get_db, Base
from db import models, schemas
from core import security, email


# Create in-memory SQLite database for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """Override database dependency for testing"""
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


# Override the database dependency
app.dependency_overrides[get_db] = override_get_db

# Create test client
client = TestClient(app)


class TestAuthRouter:
    """Test class for auth router endpoints"""
    
    @classmethod
    def setup_class(cls):
        """Set up test database"""
        Base.metadata.create_all(bind=engine)
        cls.test_user_data = {
            "email": "test@example.com",
            "first_name": "Test",
            "last_name": "User",
            "password": "testpassword123"
        }
        cls.test_user_data2 = {
            "email": "test2@example.com",
            "first_name": "Test2",
            "last_name": "User2",
            "password": "testpassword456"
        }
    
    @classmethod
    def teardown_class(cls):
        """Clean up test database"""
        Base.metadata.drop_all(bind=engine)
    
    def setup_method(self):
        """Set up before each test method"""
        # Clear database before each test
        db = TestingSessionLocal()
        db.query(models.OTP).delete()
        db.query(models.User).delete()
        db.commit()
        db.close()
    
    @patch('core.email.send_otp_email')
    def test_register_success(self, mock_send_email):
        """Test successful user registration"""
        mock_send_email.return_value = None
        
        response = client.post("/auth/register", json=self.test_user_data)
        
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == self.test_user_data["email"]
        assert data["first_name"] == self.test_user_data["first_name"]
        assert data["last_name"] == self.test_user_data["last_name"]
        assert data["is_verified"] == False
        assert "id" in data
        
        # Verify email was sent
        mock_send_email.assert_called_once()
    
    def test_register_duplicate_email(self):
        """Test registration with duplicate email"""
        # Register first user
        with patch('core.email.send_otp_email'):
            client.post("/auth/register", json=self.test_user_data)
        
        # Try to register with same email
        response = client.post("/auth/register", json=self.test_user_data)
        
        assert response.status_code == 400
        assert "Email already exists" in response.json()["detail"]
    
    @patch('core.email.send_otp_email')
    def test_register_email_failure(self, mock_send_email):
        """Test registration when email sending fails"""
        mock_send_email.side_effect = Exception("Email service down")
        
        response = client.post("/auth/register", json=self.test_user_data)
        
        assert response.status_code == 500
        assert "Failed to send verification email" in response.json()["detail"]
    
    def test_verify_email_success(self):
        """Test successful email verification"""
        # Register user first
        with patch('core.email.send_otp_email'):
            client.post("/auth/register", json=self.test_user_data)
        
        # Get the OTP from database
        db = TestingSessionLocal()
        user = db.query(models.User).filter(models.User.email == self.test_user_data["email"]).first()
        otp_record = db.query(models.OTP).filter(models.OTP.user_id == user.id).first()
        db.close()
        
        # Verify email
        verify_data = {
            "email": self.test_user_data["email"],
            "otp_code": otp_record.code
        }
        response = client.post("/auth/verify-email", json=verify_data)
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Email verified successfully"
        assert data["email"] == self.test_user_data["email"]
        
        # Check user is now verified
        db = TestingSessionLocal()
        user = db.query(models.User).filter(models.User.email == self.test_user_data["email"]).first()
        assert user.is_verified == True
        db.close()
    
    def test_verify_email_invalid_otp(self):
        """Test email verification with invalid OTP"""
        # Register user first
        with patch('core.email.send_otp_email'):
            client.post("/auth/register", json=self.test_user_data)
        
        # Try to verify with wrong OTP
        verify_data = {
            "email": self.test_user_data["email"],
            "otp_code": "000000"
        }
        response = client.post("/auth/verify-email", json=verify_data)
        
        assert response.status_code == 400
        assert "Invalid or expired OTP code" in response.json()["detail"]
    
    @patch('core.email.send_otp_email')
    def test_resend_otp_success(self, mock_send_email):
        """Test successful OTP resend"""
        # Register user first
        client.post("/auth/register", json=self.test_user_data)
        
        # Resend OTP
        response = client.post("/auth/resend-otp", params={"email_address": self.test_user_data["email"]})
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "OTP sent successfully"
        assert data["email"] == self.test_user_data["email"]
        
        # Verify email was sent
        mock_send_email.assert_called()
    
    def test_resend_otp_user_not_found(self):
        """Test OTP resend for non-existent user"""
        response = client.post("/auth/resend-otp", params={"email_address": "nonexistent@example.com"})
        
        assert response.status_code == 404
        assert "User not found" in response.json()["detail"]
    
    def test_login_success(self):
        """Test successful login"""
        # Register and verify user first
        with patch('core.email.send_otp_email'):
            client.post("/auth/register", json=self.test_user_data)
        
        # Get OTP and verify email
        db = TestingSessionLocal()
        user = db.query(models.User).filter(models.User.email == self.test_user_data["email"]).first()
        user.is_verified = True
        db.commit()
        db.close()
        
        # Login using the new login endpoint
        login_data = {
            "email": self.test_user_data["email"],
            "password": self.test_user_data["password"]
        }
        response = client.post("/auth/login", json=login_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "user_id" in data
    
    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        login_data = {
            "email": "wrong@example.com",
            "password": "wrongpassword"
        }
        response = client.post("/auth/login", json=login_data)
        
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]
    
    def test_login_unverified_user(self):
        """Test login with unverified user"""
        # Register user without verifying
        with patch('core.email.send_otp_email'):
            client.post("/auth/register", json=self.test_user_data)
        
        # Try to login
        login_data = {
            "email": self.test_user_data["email"],
            "password": self.test_user_data["password"]
        }
        response = client.post("/auth/login", json=login_data)
        
        assert response.status_code == 400
        assert "Please verify your email before logging in" in response.json()["detail"]
    
    @patch('core.email.send_password_reset_email')
    def test_forgot_password_success(self, mock_send_email):
        """Test successful forgot password request"""
        # Register and verify user first
        with patch('core.email.send_otp_email'):
            client.post("/auth/register", json=self.test_user_data)
        
        # Verify user
        db = TestingSessionLocal()
        user = db.query(models.User).filter(models.User.email == self.test_user_data["email"]).first()
        user.is_verified = True
        db.commit()
        db.close()
        
        # Request password reset
        forgot_data = {"email": self.test_user_data["email"]}
        response = client.post("/auth/forgot-password", json=forgot_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "Password reset code sent successfully" in data["message"]
        assert data["email"] == self.test_user_data["email"]
        
        # Verify email was sent
        mock_send_email.assert_called_once()
    
    def test_forgot_password_unverified_user(self):
        """Test forgot password for unverified user"""
        # Register user without verifying
        with patch('core.email.send_otp_email'):
            client.post("/auth/register", json=self.test_user_data)
        
        # Request password reset
        forgot_data = {"email": self.test_user_data["email"]}
        response = client.post("/auth/forgot-password", json=forgot_data)
        
        assert response.status_code == 400
        assert "Please verify your email first" in response.json()["detail"]
    
    def test_forgot_password_nonexistent_user(self):
        """Test forgot password for non-existent user"""
        forgot_data = {"email": "nonexistent@example.com"}
        response = client.post("/auth/forgot-password", json=forgot_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "If the email exists" in data["message"]
    
    def test_reset_password_success(self):
        """Test successful password reset"""
        # Register and verify user first
        with patch('core.email.send_otp_email'):
            client.post("/auth/register", json=self.test_user_data)
        
        # Verify user
        db = TestingSessionLocal()
        user = db.query(models.User).filter(models.User.email == self.test_user_data["email"]).first()
        user.is_verified = True
        db.commit()
        db.close()
        
        # Request password reset to get OTP
        with patch('core.email.send_password_reset_email'):
            client.post("/auth/forgot-password", json={"email": self.test_user_data["email"]})
        
        # Get the OTP from database
        db = TestingSessionLocal()
        user = db.query(models.User).filter(models.User.email == self.test_user_data["email"]).first()
        otp_record = db.query(models.OTP).filter(models.OTP.user_id == user.id).first()
        db.close()
        
        # Reset password
        reset_data = {
            "email": self.test_user_data["email"],
            "otp_code": otp_record.code,
            "new_password": "newpassword123"
        }
        response = client.post("/auth/reset-password", json=reset_data)
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Password reset successfully"
        
        # Verify password was changed
        db = TestingSessionLocal()
        user = db.query(models.User).filter(models.User.email == self.test_user_data["email"]).first()
        assert security.verify_password("newpassword123", user.hashed_password)
        db.close()
    
    def test_reset_password_invalid_otp(self):
        """Test password reset with invalid OTP"""
        # Register and verify user first
        with patch('core.email.send_otp_email'):
            client.post("/auth/register", json=self.test_user_data)
        
        db = TestingSessionLocal()
        user = db.query(models.User).filter(models.User.email == self.test_user_data["email"]).first()
        user.is_verified = True
        db.commit()
        db.close()
        
        # Try to reset with wrong OTP
        reset_data = {
            "email": self.test_user_data["email"],
            "otp_code": "000000",
            "new_password": "newpassword123"
        }
        response = client.post("/auth/reset-password", json=reset_data)
        
        assert response.status_code == 400
        assert "Invalid or expired OTP code" in response.json()["detail"]
    
    def test_change_password_success(self):
        """Test successful password change for authenticated user"""
        # Register and verify user first
        with patch('core.email.send_otp_email'):
            client.post("/auth/register", json=self.test_user_data)
        
        # Verify user
        db = TestingSessionLocal()
        user = db.query(models.User).filter(models.User.email == self.test_user_data["email"]).first()
        user.is_verified = True
        db.commit()
        db.close()
        
        # Login to get access token
        login_data = {
            "email": self.test_user_data["email"],
            "password": self.test_user_data["password"]
        }
        login_response = client.post("/auth/login", json=login_data)
        access_token = login_response.json()["access_token"]
        
        # Change password
        change_data = {
            "current_password": self.test_user_data["password"],
            "new_password": "newpassword123"
        }
        headers = {"Authorization": f"Bearer {access_token}"}
        response = client.post("/auth/change-password", json=change_data, headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Password changed successfully"
        
        # Verify password was changed
        db = TestingSessionLocal()
        user = db.query(models.User).filter(models.User.email == self.test_user_data["email"]).first()
        assert security.verify_password("newpassword123", user.hashed_password)
        db.close()
    
    def test_change_password_wrong_current_password(self):
        """Test password change with wrong current password"""
        # Register and verify user first
        with patch('core.email.send_otp_email'):
            client.post("/auth/register", json=self.test_user_data)
        
        # Verify user
        db = TestingSessionLocal()
        user = db.query(models.User).filter(models.User.email == self.test_user_data["email"]).first()
        user.is_verified = True
        db.commit()
        db.close()
        
        # Login to get access token
        login_data = {
            "email": self.test_user_data["email"],
            "password": self.test_user_data["password"]
        }
        login_response = client.post("/auth/login", json=login_data)
        access_token = login_response.json()["access_token"]
        
        # Try to change password with wrong current password
        change_data = {
            "current_password": "wrongpassword",
            "new_password": "newpassword123"
        }
        headers = {"Authorization": f"Bearer {access_token}"}
        response = client.post("/auth/change-password", json=change_data, headers=headers)
        
        assert response.status_code == 400
        assert "Current password is incorrect" in response.json()["detail"]
    
    def test_change_password_unauthorized(self):
        """Test password change without authentication"""
        change_data = {
            "current_password": "oldpassword",
            "new_password": "newpassword123"
        }
        response = client.post("/auth/change-password", json=change_data)
        
        assert response.status_code == 401
        assert "Not authenticated" in response.json()["detail"]


def run_tests():
    """Run all tests"""
    print("🧪 Running Auth Router Tests...")
    print("=" * 50)
    
    # Create test instance
    test_instance = TestAuthRouter()
    test_instance.setup_class()
    
    # List of test methods
    test_methods = [
        "test_register_success",
        "test_register_duplicate_email",
        "test_register_email_failure",
        "test_verify_email_success",
        "test_verify_email_invalid_otp",
        "test_resend_otp_success",
        "test_resend_otp_user_not_found",
        "test_login_success",
        "test_login_invalid_credentials",
        "test_login_unverified_user",
        "test_forgot_password_success",
        "test_forgot_password_unverified_user",
        "test_forgot_password_nonexistent_user",
        "test_reset_password_success",
        "test_reset_password_invalid_otp",
        "test_change_password_success",
        "test_change_password_wrong_current_password",
        "test_change_password_unauthorized"
    ]
    
    passed = 0
    failed = 0
    
    for method_name in test_methods:
        try:
            print(f"Testing {method_name}...", end=" ")
            test_instance.setup_method()
            getattr(test_instance, method_name)()
            print("✅ PASSED")
            passed += 1
        except Exception as e:
            print(f"❌ FAILED: {str(e)}")
            failed += 1
    
    print("=" * 50)
    print(f"📊 Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests passed!")
    else:
        print("⚠️  Some tests failed. Please check the implementation.")
    
    test_instance.teardown_class()
    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1) 