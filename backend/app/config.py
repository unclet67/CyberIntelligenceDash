from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "ARGUS TI API"
    environment: str = "development"
    database_url: str = "sqlite:///./cyberintel.db"
    cors_origins: str = "http://localhost:8000,http://127.0.0.1:8000"
    seed_on_startup: bool = True

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
