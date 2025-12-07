from pydantic import model_validator, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Auth Service configuration settings."""
    
    # Database connection parameters
    DB_HOST: str = "auth-db"
    DB_PORT: int = 5432
    DB_NAME: str = "auth_db"
    DB_USER: str = "postgres"
    DB_PASSWORD: str = "postgres"
    
    # Redis connection parameters
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    
    # Backward compatibility: if DATABASE_URL is provided, it takes precedence
    # DATABASE_URL: str | None = None
    
    # JWT settings
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 15
    JWT_REFRESH_EXPIRATION_DAYS: int = 7
    ISSUER: str = "auth-service"
    AUDIENCE: str = "fastapi-app"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )

    @computed_field
    @property
    def database_url(self) -> str:
        """Construct database URL from individual parameters or use provided URL."""
        # if self.DATABASE_URL:
        #     return self.DATABASE_URL
        return f"postgresql+asyncpg://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    @model_validator(mode='after')
    def validate_jwt_secret(self):
        """Validate JWT secret key length for security."""
        if len(self.JWT_SECRET_KEY) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters for security")
        return self


settings = Settings()
