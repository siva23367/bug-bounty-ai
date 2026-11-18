import os
from pathlib import Path

from cryptography.fernet import Fernet
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')
    data_dir: Path = Path('data')
    database_url: str = 'sqlite:///data/bugbounty.db'
    api_token: str = ''
    encryption_key: str = ''
    allow_loopback_targets: bool = False
    frontend_dir: Path = Path('frontend/dist')
    llm_base_url: str = ''
    llm_api_key: str = ''
    llm_model: str = ''
    hackerone_username: str = ''
    hackerone_token: str = ''
    bugcrowd_token: str = ''
    intigriti_token: str = ''
    callback_base_url: str = ''


settings = Settings()


def persistent_secret(name: str, supplied: str, factory) -> str:
    if supplied:
        return supplied
    settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = settings.data_dir / name
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_text().strip()
    value = factory()
    with os.fdopen(fd, 'w') as stream:
        stream.write(value)
    return value


def cipher() -> Fernet:
    return Fernet(persistent_secret('encryption.key', settings.encryption_key,
                                   lambda: Fernet.generate_key().decode()).encode())
