# Backward compatibility - imports from new structure
from .services.auth_service import AuthService

# Re-export commonly used functions for backward compatibility
hash_password = AuthService.hash_password
verify_password = AuthService.verify_password
create_tokens = AuthService.create_tokens
verify_access_token = AuthService.verify_access_token
verify_refresh_token = AuthService.verify_refresh_token

__all__ = [
    "hash_password",
    "verify_password", 
    "create_tokens",
    "verify_access_token",
    "verify_refresh_token",
]
