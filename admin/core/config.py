from logging import config as logging_config

from core.logger import LOGGING  # type: ignore
from pydantic import BaseSettings

logging_config.dictConfig(LOGGING)


class Settings(BaseSettings):
    AUTH_REDIS: str
    AUTH_REDIS_PORT: int
    AUTH_POSTGRES_HOST: str
    AUTH_POSTGRES_PORT: int
    AUTH_POSTGRES_DB: str
    AUTH_POSTGRES_USER: str
    AUTH_POSTGRES_PASSWORD: str
    TTL_ACCESS_TOKEN: int
    TTL_REFRESH_TOKEN: int
    TTL_CAPTCHA_TOKEN = 600
    JWT_KEY: str
    ROLES_FOR_ADMIN_EDIT = ['subscriber', 'unsubscriber']
    APP_VK_ID = '51409340'
    APP_YANDEX_ID = '56ed84450c9b4be9a042c36748637973'
    MY_SITE_URL = 'https://oauth.vk.com/blank.html'
    RATE_LIMIT_DEFAULT_SEC: list
    RATE_LIMIT_TOKEN: str
    RATE_LIMIT_USERS: str
    RATE_LIMIT_VK: str
    RATE_LIMIT_YA: str
    TEST_CASE = "SuperPuperTestKeyForTest"
    TEST_CASE_WITHOUT_EMAIL = "SuperPuperTestKeyForTestNoEmail"
    TRACER_ON = False

    class Config:
        env_file = '.env'


settings = Settings()
