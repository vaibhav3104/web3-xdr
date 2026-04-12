"""
JWT Token Handler for Sentinel3 Authentication.
"""

import os
import re
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import jwt
from fastapi import HTTPException, Security, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import structlog

from .models import User, UserInDB, TokenData

logger = structlog.get_logger()

# Security scheme
security = HTTPBearer(auto_error=False)

# Password complexity: min 8 chars, 1 upper, 1 lower, 1 digit
_PASSWORD_PATTERN = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$')


def validate_password(password: str) -> None:
    """Raise ValueError if password doesn't meet complexity rules."""
    if not _PASSWORD_PATTERN.match(password):
        raise ValueError(
            "Password must be at least 8 characters with 1 uppercase, "
            "1 lowercase, and 1 digit"
        )


class TokenBlacklist:
    """
    Redis-backed token blacklist with in-memory fallback.
    Revoked JTIs are stored until their natural expiry.
    """

    def __init__(self):
        self._memory: Dict[str, float] = {}  # jti -> expiry timestamp
        self._redis = None

    async def _get_redis(self):
        if self._redis is not None:
            return self._redis
        try:
            import redis.asyncio as aioredis
            url = os.getenv("REDIS_URL", "redis://localhost:6379")
            self._redis = aioredis.from_url(url, decode_responses=True)
            await self._redis.ping()
            return self._redis
        except (ConnectionError, OSError, ImportError):
            self._redis = None
            return None

    async def revoke(self, jti: str, exp_timestamp: float) -> None:
        """Add a token JTI to the blacklist."""
        ttl = max(int(exp_timestamp - datetime.now(timezone.utc).timestamp()), 0)
        r = await self._get_redis()
        if r:
            try:
                await r.setex(f"blacklist:{jti}", ttl, "1")
                return
            except (ConnectionError, OSError):
                pass
        # Fallback: in-memory
        self._memory[jti] = exp_timestamp
        # Evict expired entries
        now = datetime.now(timezone.utc).timestamp()
        self._memory = {k: v for k, v in self._memory.items() if v > now}

    async def is_revoked(self, jti: str) -> bool:
        r = await self._get_redis()
        if r:
            try:
                return await r.exists(f"blacklist:{jti}") > 0
            except (ConnectionError, OSError):
                pass
        return self._memory.get(jti, 0) > datetime.now(timezone.utc).timestamp()


# Singleton blacklist
token_blacklist = TokenBlacklist()


class JWTHandler:
    """
    JWT Token Handler for authentication.
    """

    # Default demo users — only loaded when ENVIRONMENT != production
    _DEMO_USERS: Dict[str, Dict[str, Any]] = {
        "admin": {
            "username": "admin",
            "email": "admin@web3xdr.io",
            "full_name": "Administrator",
            "role": "admin",
            "disabled": False,
            "hashed_password": hashlib.sha256("admin123".encode()).hexdigest()
        },
        "operator": {
            "username": "operator",
            "email": "operator@web3xdr.io",
            "full_name": "Security Operator",
            "role": "operator",
            "disabled": False,
            "hashed_password": hashlib.sha256("operator123".encode()).hexdigest()
        },
        "viewer": {
            "username": "viewer",
            "email": "viewer@web3xdr.io",
            "full_name": "Dashboard Viewer",
            "role": "viewer",
            "disabled": False,
            "hashed_password": hashlib.sha256("viewer123".encode()).hexdigest()
        }
    }

    def __init__(
        self,
        secret_key: Optional[str] = None,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 60
    ):
        env = os.getenv("ENVIRONMENT", "development")
        configured_secret = secret_key or os.getenv("JWT_SECRET_KEY", "")

        # In production, require an explicit secret
        if env == "production" and not configured_secret:
            raise RuntimeError(
                "JWT_SECRET_KEY environment variable is required in production. "
                "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
            )

        # In dev, generate a random secret per-process if none set (never use a static default)
        self.secret_key = configured_secret or secrets.token_urlsafe(48)
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes

        # User store: only load demo users outside production
        self.users: Dict[str, Dict[str, Any]] = {}
        if env != "production":
            self.users = self._DEMO_USERS.copy()
            logger.warning("demo_users_loaded", hint="Set ENVIRONMENT=production to disable")

        # Load users from environment variables (works in all environments)
        self._load_env_users()

        if not self.users:
            logger.error("no_users_configured", hint="Set XDR_USER_<name>=<password>:<role> env vars")

        logger.info(
            "jwt_handler_initialized",
            algorithm=algorithm,
            token_expire_minutes=access_token_expire_minutes,
            user_count=len(self.users),
            environment=env
        )
    
    def _load_env_users(self):
        """Load users from environment variables."""
        # Format: XDR_USER_<username>=<password>:<role>
        for key, value in os.environ.items():
            if key.startswith("XDR_USER_"):
                username = key.replace("XDR_USER_", "").lower()
                parts = value.split(":")
                password = parts[0]
                role = parts[1] if len(parts) > 1 else "viewer"
                
                self.users[username] = {
                    "username": username,
                    "email": f"{username}@web3xdr.io",
                    "full_name": username.title(),
                    "role": role,
                    "disabled": False,
                    "hashed_password": hashlib.sha256(password.encode()).hexdigest()
                }
                logger.info("loaded_user_from_env", username=username, role=role)
    
    def hash_password(self, password: str) -> str:
        """Hash a password."""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return self.hash_password(plain_password) == hashed_password
    
    def get_user(self, username: str) -> Optional[UserInDB]:
        """Get user by username."""
        if username in self.users:
            user_data = self.users[username]
            return UserInDB(**user_data)
        return None
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate a user with username and password."""
        user = self.get_user(username)
        if not user:
            logger.warning("auth_failed_user_not_found", username=username)
            return None
        if not self.verify_password(password, user.hashed_password):
            logger.warning("auth_failed_invalid_password", username=username)
            return None
        if user.disabled:
            logger.warning("auth_failed_user_disabled", username=username)
            return None
        
        logger.info("auth_success", username=username, role=user.role)
        return User(
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            disabled=user.disabled
        )
    
    def create_access_token(
        self,
        data: dict,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create a JWT access token."""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "jti": secrets.token_hex(16)  # Unique token ID
        })
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        
        logger.info(
            "token_created",
            username=data.get("sub"),
            expires=expire.isoformat()
        )
        
        return encoded_jwt
    
    def decode_token(self, token: str) -> Optional[TokenData]:
        """Decode and verify a JWT token."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            username: str = payload.get("sub")
            role: str = payload.get("role")
            exp = payload.get("exp")
            jti: str = payload.get("jti")

            if username is None:
                return None

            return TokenData(
                username=username,
                role=role,
                exp=datetime.fromtimestamp(exp) if exp else None,
                jti=jti
            )
        except jwt.ExpiredSignatureError:
            logger.warning("token_expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning("token_invalid", error=str(e))
            return None

    async def revoke_token(self, token: str) -> bool:
        """Revoke a token by adding its JTI to the blacklist."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            jti = payload.get("jti")
            exp = payload.get("exp", 0)
            if jti:
                await token_blacklist.revoke(jti, exp)
                logger.info("token_revoked", jti=jti)
                return True
        except jwt.InvalidTokenError:
            pass
        return False
    
    def create_user(
        self,
        username: str,
        password: str,
        email: Optional[str] = None,
        full_name: Optional[str] = None,
        role: str = "viewer"
    ) -> User:
        """Create a new user."""
        if username in self.users:
            raise ValueError(f"User {username} already exists")

        validate_password(password)

        self.users[username] = {
            "username": username,
            "email": email or f"{username}@web3xdr.io",
            "full_name": full_name or username.title(),
            "role": role,
            "disabled": False,
            "hashed_password": self.hash_password(password)
        }
        
        logger.info("user_created", username=username, role=role)
        
        return User(
            username=username,
            email=self.users[username]["email"],
            full_name=self.users[username]["full_name"],
            role=role,
            disabled=False
        )
    
    def delete_user(self, username: str) -> bool:
        """Delete a user."""
        if username not in self.users:
            return False
        
        # Prevent deleting the last admin
        if self.users[username]["role"] == "admin":
            admin_count = sum(1 for u in self.users.values() if u["role"] == "admin")
            if admin_count <= 1:
                raise ValueError("Cannot delete the last admin user")
        
        del self.users[username]
        logger.info("user_deleted", username=username)
        return True
    
    def change_password(self, username: str, current_password: str, new_password: str) -> bool:
        """Change user password."""
        user = self.get_user(username)
        if not user:
            return False

        if not self.verify_password(current_password, user.hashed_password):
            return False

        validate_password(new_password)

        self.users[username]["hashed_password"] = self.hash_password(new_password)
        logger.info("password_changed", username=username)
        return True
    
    def list_users(self) -> list:
        """List all users (without passwords)."""
        return [
            User(
                username=u["username"],
                email=u["email"],
                full_name=u["full_name"],
                role=u["role"],
                disabled=u["disabled"]
            )
            for u in self.users.values()
        ]


# Global JWT handler instance
jwt_handler = JWTHandler()


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security)
) -> Optional[User]:
    """
    Get current user from JWT token.
    Returns None if no token or invalid token.
    """
    if credentials is None:
        return None
    
    token = credentials.credentials
    token_data = jwt_handler.decode_token(token)
    
    if token_data is None:
        return None
    
    user = jwt_handler.get_user(token_data.username)
    if user is None:
        return None
    
    return User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        disabled=user.disabled
    )


async def require_auth(
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> User:
    """
    Require authentication. Raises 401 if not authenticated.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = credentials.credentials
    token_data = jwt_handler.decode_token(token)

    if token_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Check token blacklist (revoked tokens)
    if token_data.jti and await token_blacklist.is_revoked(token_data.jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user = jwt_handler.get_user(token_data.username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if user.disabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )

    return User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        disabled=user.disabled
    )


def require_role(allowed_roles: list):
    """
    Decorator to require specific roles.
    """
    async def role_checker(user: User = Depends(require_auth)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {allowed_roles}"
            )
        return user
    return role_checker

