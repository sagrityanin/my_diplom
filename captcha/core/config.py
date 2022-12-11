from logging import config as logging_config

from core.logger import LOGGING
from pydantic import BaseSettings

logging_config.dictConfig(LOGGING)


class Settings(BaseSettings):
    AUTH_REDIS: str
    AUTH_REDIS_PORT: int
    TTL_ACCESS_TOKEN: int
    TTL_REFRESH_TOKEN: int
    TTL_CAPTCHA_TOKEN = 600
    JWT_KEY: str

    class Config:
        env_file = '.env'


settings = Settings()
