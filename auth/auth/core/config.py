from logging import config as logging_config
from pydantic import BaseSettings

from core.logger import LOGGING  # type: ignore

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
    TTL_CONFIRM_EMAIL = 10
    TINYURL = "https://api.tinyurl.com/create"
    TINYURL_TOKEN = "6wG90PcZZRmf41cxUlIjFejwAFedTOtXUL1ys2WeoTkBKnBC3deoWmTGZ4Us"
    TINYURL_DOMAIN = "tiny.one"
    NOTIFICATION_URL = "reviews:8000"
    NGINX_AUTH_URL = "nginx-auth:80"
    TEST_DOMEN = "co.com"
    MONGO_DSN = "mongodb://mongo:27017/"
    MONGO_DB = "films_summary"
    MONGO_NOTIFICATION_COLLECTION = "email_notification"
    NOTIFICATION_QUEUE = "email.notification"
    REBBITMQ_HOST = "rabbitmq"
    REBBITMQ_PORT = 5672

    class Config:
        env_file = '.env'


settings = Settings()
