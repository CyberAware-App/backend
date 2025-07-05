from pydantic import BaseModel, EmailStr
from typing import Optional, List

class UserCreate(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str
    password: str
    
class UserLogin(BaseModel):
    email: EmailStr
    password: str
    
class UserResponse(BaseModel):
    id: int
    email: EmailStr
    first_name: str
    last_name: str
    is_verified: bool
    
    class Config:
        model_config = {
            "from_attributes": True
        }


class OTPVerify(BaseModel):
    email: EmailStr
    otp_code: str

class OTPResponse(BaseModel):
    message: str
    email: EmailStr


class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    otp_code: str
    new_password: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class PasswordResponse(BaseModel):
    message: str


class Token(BaseModel):
    access_token: str
    token_type: str
    user_id: int

class TokenData(BaseModel):
    email: Optional[EmailStr] = None
    
    
class ModuleResponse(BaseModel):
    id: int
    title: str
    description: str
    content: dict
    
    class Config:
        model_config = {
            "from_attributes": True
        }
    
class ModuleCompleted(BaseModel):
    module_id: int
    is_completed: bool
    
    
class QuizResponse(BaseModel):
    id: int
    module_id: int
    questions: List[dict]
    answers: List[dict]
    
    class Config:
        model_config = {
            "from_attributes": True
        }
    
    
class FeedbackCreate(BaseModel):
    content: str
