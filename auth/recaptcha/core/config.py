from logging import config as logging_config
from pydantic import BaseSettings

from core.logger import LOGGING

logging_config.dictConfig(LOGGING)


class Settings(BaseSettings):
    AUTH_REDIS: str
    AUTH_REDIS_PORT: int
    TTL_ACCESS_TOKEN: int
    TTL_REFRESH_TOKEN: int
    TTL_CAPTCHA_TOKEN = 600
    JWT_KEY: str
    RECAPTCHA_PUBLIC_KEY = "6LdVf-chAAAAAO89g-cqf8p7D1U1QNwnDGxU4POY"
    RECAPTCHA_PRIVATE_KEY = "6LdVf-chAAAAAMxBStQTJXVxBDi_nT1D9Mel2eAt"
    SECRET_KEY = "sdfgdfhfghfn,gbhcv,nb /,mnl.bjl vb"

    class Config:
        env_file = '.env'


settings = Settings()
