from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "ARGUS TI API"
    environment: str = "development"
    database_url: str = "sqlite:///./cyberintel.db"
    cors_origins: str = "http://localhost:8000,http://127.0.0.1:8000"
    seed_on_startup: bool = True
    auth_required: bool = False
    api_auth_token: str | None = None
    mitre_stix_url: str = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "master/enterprise-attack/enterprise-attack.json"
    )
    malpedia_base_url: str = "https://malpedia.caad.fkie.fraunhofer.de"
    malpedia_api_token: str | None = None
    threatfox_api_url: str = "https://threatfox-api.abuse.ch/api/v1/"
    abusech_auth_key: str | None = None
    threatfox_days: int = 7
    stix_feed_url: str | None = None
    ingestion_interval_seconds: int = 3600
    request_timeout_seconds: float = 120.0

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
