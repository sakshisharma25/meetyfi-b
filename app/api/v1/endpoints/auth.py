from fastapi import APIRouter, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse
from app.core.security import create_access_token
from app.models.user import UserInDB, UserBase
from app.db.mongodb import get_database
from datetime import timedelta
from app.config import get_settings
from email_validator import validate_email, EmailNotValidError
import random
from app.core.email_utils import EmailService


router = APIRouter()
settings = get_settings()
email_service = EmailService()


@router.post("/signup")
async def signup(user: UserBase):
    db = await get_database()
    
    try:
        # Validate email format
        valid = validate_email(user.email)
        user.email = valid.email
    except EmailNotValidError:
        raise HTTPException(
            status_code=400,
            detail="Invalid email format"
        )
    
    # Check if email exists
    if await db.users.find_one({"email": user.email}):
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )
    
    # Generate OTP
    otp = str(random.randint(100000, 999999))
    
    # Create user
    user_dict = user.dict()
    user_dict["verification_code"] = otp
    user_dict["is_verified"] = False
    user_dict["is_manager"] = False  # Default to regular user
    
    await db.users.insert_one(user_dict)
    
    # Send verification email
    await email_service.send_verification_email(user.email, otp)
    
    return {"message": "Signup successful. Please verify your email."}

@router.post("/verify-email")
async def verify_email(
    email: str = Form(...),
    otp: str = Form(...)
):
    db = await get_database()
    user = await db.users.find_one({"email": email})
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    if user["verification_code"] != otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
        
    await db.users.update_one(
        {"email": email},
        {
            "$set": {
                "is_verified": True,
                "verification_code": None  # Clear the OTP after verification
            }
        }
    )
    
    return {"message": "Email verified successfully"}

@router.post("/login")
async def login(email: str = Form(...)):
    db = await get_database()
    user = await db.users.find_one({"email": email})
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if not user.get("is_verified", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified"
        )
    
    # Generate and send OTP
    otp = str(random.randint(100000, 999999))
    await email_service.send_verification_email(user["email"], otp)
    
    # Store OTP
    await db.users.update_one(
        {"email": email},
        {"$set": {"verification_code": otp}}
    )
    
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "OTP sent to your email. Please verify to login."}
    )

@router.post("/verify-login")
async def verify_login(
    email: str = Form(...),
    otp: str = Form(...)
):
    db = await get_database()
    user = await db.users.find_one({"email": email})
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if not user.get("is_verified", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified"
        )
    
    if user["verification_code"] != otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    # Clear the OTP after successful verification
    await db.users.update_one(
        {"email": email},
        {"$set": {"verification_code": None}}
    )
    
    # Generate access token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"]}, expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }