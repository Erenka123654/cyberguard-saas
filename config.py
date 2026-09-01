import secrets
import warnings
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    jwt_secret: str = "dev-secret"
    database_url: str = "sqlite:///./cyberguard.db"
    # Comma-separated list of allowed frontend origins, e.g. "https://app.example.com,https://example.com"
    frontend_origin: str = "http://localhost:5500,http://127.0.0.1:5500"
    admin_email: str = "admin@example.com"
    class Config:
        env_file = ".env"

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.frontend_origin.split(",") if o.strip()]

settings = Settings()

if settings.jwt_secret == "dev-secret":
    warnings.warn(
        "SECURITY WARNING: JWT_SECRET is not set (using the insecure default 'dev-secret'). "
        "Set a strong random JWT_SECRET in your .env before deploying to production. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\"",
        stacklevel=2,
    )
