from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    jwt_secret: str = "dev-secret"
    database_url: str = "sqlite:///./cyberguard.db"
    frontend_origin: str = "*"
    admin_email: str = "admin@example.com"
    class Config:
        env_file = ".env"

settings = Settings()
