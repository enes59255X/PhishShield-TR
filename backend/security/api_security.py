"""
API Security - Authentication and Authorization
PhishShield TR V3

Provides:
- API Key authentication
- JWT token management
- Request validation
"""

import secrets
import hashlib
import hmac
import time
import json
import base64
from typing import Optional, Dict, Any, Callable
from dataclasses import dataclass
from enum import Enum
from functools import wraps


class AuthMethod(Enum):
    NONE = "none"
    API_KEY = "api_key"
    JWT = "jwt"
    ADMIN = "admin"


@dataclass
class TokenData:
    """JWT Token data"""
    user_id: str
    tier: str
    permissions: list
    exp: float


@dataclass
class AuthResult:
    """Authentication result"""
    success: bool
    method: AuthMethod
    user_id: Optional[str] = None
    tier: Optional[str] = None
    error: Optional[str] = None


class APIKeyManager:
    """
    Manages API keys for authentication.
    
    Features:
    - Key generation (SHA256 based)
    - Key validation
    - Tier-based access control
    - Key rotation support
    """

    TIERS = {
        "free": {"requests_per_minute": 10, "requests_per_day": 100},
        "basic": {"requests_per_minute": 60, "requests_per_day": 5000},
        "premium": {"requests_per_minute": 300, "requests_per_day": 50000},
        "enterprise": {"requests_per_minute": 1000, "requests_per_day": 500000},
    }

    def __init__(self, storage_path: str = "data/api_keys.json"):
        self.storage_path = storage_path
        self._keys: Dict[str, Dict] = {}
        self._load_keys()

    def _load_keys(self):
        """Load keys from storage"""
        try:
            with open(self.storage_path, "r") as f:
                self._keys = json.load(f)
        except FileNotFoundError:
            self._keys = {}

    def _save_keys(self):
        """Save keys to storage"""
        import os
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        with open(self.storage_path, "w") as f:
            json.dump(self._keys, f, indent=2)

    def generate_key(self, user_id: str, tier: str = "free") -> str:
        """
        Generate a new API key.
        
        Args:
            user_id: User identifier
            tier: Access tier (free/basic/premium/enterprise)
            
        Returns:
            API key string
        """
        key = f"psh_{secrets.token_urlsafe(32)}"
        key_hash = self._hash_key(key)
        
        self._keys[key_hash] = {
            "user_id": user_id,
            "tier": tier,
            "created": time.time(),
            "last_used": None,
            "requests_count": 0,
            "active": True,
        }
        
        self._save_keys()
        return key

    def validate_key(self, key: str) -> AuthResult:
        """
        Validate an API key.
        
        Args:
            key: API key to validate
            
        Returns:
            AuthResult with validation status
        """
        if not key:
            return AuthResult(
                success=False,
                method=AuthMethod.NONE,
                error="No API key provided"
            )

        key_hash = self._hash_key(key)
        key_data = self._keys.get(key_hash)

        if not key_data:
            return AuthResult(
                success=False,
                method=AuthMethod.API_KEY,
                error="Invalid API key"
            )

        if not key_data.get("active", False):
            return AuthResult(
                success=False,
                method=AuthMethod.API_KEY,
                error="API key is inactive"
            )

        key_data["last_used"] = time.time()
        key_data["requests_count"] = key_data.get("requests_count", 0) + 1
        self._save_keys()

        return AuthResult(
            success=True,
            method=AuthMethod.API_KEY,
            user_id=key_data["user_id"],
            tier=key_data["tier"]
        )

    def revoke_key(self, key: str) -> bool:
        """Revoke an API key"""
        key_hash = self._hash_key(key)
        if key_hash in self._keys:
            self._keys[key_hash]["active"] = False
            self._save_keys()
            return True
        return False

    def get_key_info(self, key: str) -> Optional[Dict]:
        """Get API key information"""
        key_hash = self._hash_key(key)
        return self._keys.get(key_hash)

    def get_tier_limits(self, tier: str) -> Dict:
        """Get rate limits for a tier"""
        return self.TIERS.get(tier, self.TIERS["free"])

    def _hash_key(self, key: str) -> str:
        """Hash an API key for storage"""
        return hashlib.sha256(key.encode()).hexdigest()


class JWTTokenManager:
    """
    Manages JWT tokens for authentication.
    
    Features:
    - Token generation
    - Token validation
    - Token refresh
    - Expiration handling
    """

    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.algorithm = "HS256"
        self.token_expiry = 3600  # 1 hour
        self.refresh_expiry = 86400 * 7  # 7 days

    def generate_token(
        self,
        user_id: str,
        tier: str = "free",
        permissions: Optional[list] = None
    ) -> Dict[str, str]:
        """
        Generate access and refresh tokens.
        
        Args:
            user_id: User identifier
            tier: Access tier
            permissions: List of permissions
            
        Returns:
            Dict with access_token, refresh_token, expires_in
        """
        now = time.time()
        
        access_payload = {
            "user_id": user_id,
            "tier": tier,
            "permissions": permissions or [],
            "type": "access",
            "iat": now,
            "exp": now + self.token_expiry,
        }
        
        refresh_payload = {
            "user_id": user_id,
            "type": "refresh",
            "iat": now,
            "exp": now + self.refresh_expiry,
        }
        
        def b64encode(data: dict) -> str:
            payload = base64.urlsafe_b64encode(
                json.dumps(data).encode()
            ).decode()
            return payload.rstrip("=")
        
        access_header = b64encode({"alg": self.algorithm, "typ": "JWT"})
        access_payload_encoded = b64encode(access_payload)
        access_signature = self._sign(f"{access_header}.{access_payload_encoded}")
        
        refresh_header = b64encode({"alg": self.algorithm, "typ": "JWT"})
        refresh_payload_encoded = b64encode(refresh_payload)
        refresh_signature = self._sign(f"{refresh_header}.{refresh_payload_encoded}")
        
        access_token = f"{access_header}.{access_payload_encoded}.{access_signature}"
        refresh_token = f"{refresh_header}.{refresh_payload_encoded}.{refresh_signature}"
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": self.token_expiry,
        }

    def validate_token(self, token: str) -> AuthResult:
        """
        Validate a JWT token.
        
        Args:
            token: JWT token string
            
        Returns:
            AuthResult with validation status
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return AuthResult(
                    success=False,
                    method=AuthMethod.JWT,
                    error="Invalid token format"
                )
            
            header_b64, payload_b64, signature = parts
            
            expected_sig = self._sign(f"{header_b64}.{payload_b64}")
            if not hmac.compare_digest(signature, expected_sig):
                return AuthResult(
                    success=False,
                    method=AuthMethod.JWT,
                    error="Invalid signature"
                )
            
            payload_json = base64.urlsafe_b64decode(
                payload_b64 + "=" * (4 - len(payload_b64) % 4)
            )
            payload = json.loads(payload_json)
            
            if payload.get("exp", 0) < time.time():
                return AuthResult(
                    success=False,
                    method=AuthMethod.JWT,
                    error="Token expired"
                )
            
            return AuthResult(
                success=True,
                method=AuthMethod.JWT,
                user_id=payload.get("user_id"),
                tier=payload.get("tier", "free")
            )
            
        except Exception as e:
            return AuthResult(
                success=False,
                method=AuthMethod.JWT,
                error=f"Token validation failed: {str(e)}"
            )

    def refresh_access_token(self, refresh_token: str) -> Optional[Dict[str, str]]:
        """
        Generate new access token from refresh token.
        
        Args:
            refresh_token: Refresh token
            
        Returns:
            New token dict or None if invalid
        """
        result = self.validate_token(refresh_token)
        if not result.success:
            return None
        
        return self.generate_token(
            user_id=result.user_id,
            tier=result.tier
        )

    def _sign(self, data: str) -> str:
        """Create HMAC signature"""
        import hmac
        import hashlib
        
        sig = hmac.new(
            self.secret_key.encode(),
            data.encode(),
            hashlib.sha256
        ).digest()
        
        return base64.urlsafe_b64encode(sig).decode().rstrip("=")


def require_api_key(key_manager: APIKeyManager):
    """
    Decorator for API key authentication.
    
    Usage:
        @require_api_key(key_manager)
        def my_endpoint(api_key_data):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            api_key = request.headers.get("X-API-Key")
            
            if not api_key:
                api_key = request.cookies.get("api_key")
            
            if not api_key:
                return {"error": "API key required"}, 401
            
            result = key_manager.validate_key(api_key)
            
            if not result.success:
                return {"error": result.error}, 401
            
            return func(request, result, *args, **kwargs)
        
        return wrapper
    return decorator


def require_jwt(token_manager: JWTTokenManager):
    """
    Decorator for JWT authentication.
    
    Usage:
        @require_jwt(token_manager)
        def my_endpoint(token_data):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            
            if not auth_header.startswith("Bearer "):
                return {"error": "Bearer token required"}, 401
            
            token = auth_header[7:]
            result = token_manager.validate_token(token)
            
            if not result.success:
                return {"error": result.error}, 401
            
            return func(request, result, *args, **kwargs)
        
        return wrapper
    return decorator


def get_client_ip(request) -> str:
    """Extract client IP from request"""
    x_forwarded = request.headers.get("X-Forwarded-For")
    if x_forwarded:
        return x_forwarded.split(",")[0].strip()
    
    x_real_ip = request.headers.get("X-Real-IP")
    if x_real_ip:
        return x_real_ip
    
    return request.client.host if hasattr(request, "client") else "unknown"
