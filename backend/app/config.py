from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import computed_field
from pathlib import Path
from typing import List
import json

_DEFAULT_DATABASE_PATH = Path(__file__).resolve().parents[2] / "phishguard.db"


class Settings(BaseSettings):
    database_url: str = f"sqlite+aiosqlite:///{_DEFAULT_DATABASE_PATH.as_posix()}"
    secret_key: str = "change-me-in-production"

    virustotal_api_key: str = ""
    urlhaus_api_key: str = ""
    cti_mock: bool = True

    ml_model_path: str = "ml/models/artifacts/phishguard_model.joblib"

    # stored as str so pydantic-settings never tries json.loads on it
    cors_origins: str = "http://localhost:5173,http://localhost:3000"
    host: str = "0.0.0.0"
    port: int = 8001

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @computed_field
    @property
    def cors_origins_list(self) -> List[str]:
        v = self.cors_origins.strip()
        if v.startswith("["):
            return json.loads(v)
        return [o.strip() for o in v.split(",") if o.strip()]


settings = Settings()
