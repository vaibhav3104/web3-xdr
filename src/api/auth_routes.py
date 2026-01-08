"""
Authentication API routes for Sentinel3.
"""

from typing import List
from datetime import timedelta

from fastapi import APIRouter, HTTPException, Depends, status
import structlog

from ..auth.jwt_handler import jwt_handler, require_auth, require_role
from ..auth.models import (
    User, LoginRequest, LoginResponse,
    ChangePasswordRequest, CreateUserRequest
)

logger = structlog.get_logger()
router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    """
    Authenticate user and return JWT token.
    
    Default credentials for testing:
    - admin/admin123 (full access)
    - operator/operator123 (limited admin)
    - viewer/viewer123 (read-only)
    """
    from ..database.audit import AuditLogger, ActionType
    from fastapi import Request
    
    user = jwt_handler.authenticate_user(request.username, request.password)
    
    # Get client IP
    if not client_ip:
        # Try to get from request headers (if available)
        client_ip = None  # Would need Request object
    
    if not user:
        # Log failed login
        AuditLogger.log_login(request.username, success=False, ip_address=client_ip)
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    # Log successful login
    AuditLogger.log_login(request.username, success=True, ip_address=client_ip)
    
    # Create access token
    access_token = jwt_handler.create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=timedelta(minutes=jwt_handler.access_token_expire_minutes)
    )
    
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=jwt_handler.access_token_expire_minutes * 60,
        user=user
    )


@router.post("/logout")
async def logout(current_user: User = Depends(require_auth)):
    """
    Logout user (client should discard token).
    Note: JWT tokens are stateless, so logout is handled client-side.
    For production, implement token blacklisting with Redis.
    """
    from ..database.audit import AuditLogger, ActionType
    
    AuditLogger.log(
        action_type=ActionType.LOGOUT,
        actor_id=current_user.username
    )
    
    logger.info("user_logout", username=current_user.username)
    return {"message": "Logged out successfully", "username": current_user.username}


@router.get("/me", response_model=User)
async def get_current_user_info(current_user: User = Depends(require_auth)):
    """Get current authenticated user information."""
    return current_user


@router.post("/change-password")
async def change_password(
    request: ChangePasswordRequest,
    current_user: User = Depends(require_auth)
):
    """Change current user's password."""
    success = jwt_handler.change_password(
        current_user.username,
        request.current_password,
        request.new_password
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    return {"message": "Password changed successfully"}


@router.get("/verify")
async def verify_token(current_user: User = Depends(require_auth)):
    """Verify if current token is valid."""
    return {
        "valid": True,
        "username": current_user.username,
        "role": current_user.role
    }


# Admin-only routes

@router.get("/users", response_model=List[User])
async def list_users(
    current_user: User = Depends(require_role(["admin"]))
):
    """List all users (admin only)."""
    return jwt_handler.list_users()


@router.post("/users", response_model=User)
async def create_user(
    request: CreateUserRequest,
    current_user: User = Depends(require_role(["admin"]))
):
    """Create a new user (admin only)."""
    try:
        user = jwt_handler.create_user(
            username=request.username,
            password=request.password,
            email=request.email,
            full_name=request.full_name,
            role=request.role
        )
        return user
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.delete("/users/{username}")
async def delete_user(
    username: str,
    current_user: User = Depends(require_role(["admin"]))
):
    """Delete a user (admin only)."""
    if username == current_user.username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    try:
        success = jwt_handler.delete_user(username)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        return {"message": f"User {username} deleted"}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

