from logging import config as logging_config
from pydantic import BaseSettings


class Settings(BaseSettings):
    AUTH_POSTGRES_HOST: str
    AUTH_POSTGRES_PORT: int
    AUTH_POSTGRES_DB: str
    AUTH_POSTGRES_USER: str
    AUTH_POSTGRES_PASSWORD: str
    JWT_KEY: str
    TEST_CASE = "SuperPuperTestKeyForTest"
    TEST_CASE_WITHOUT_EMAIL = "SuperPuperTestKeyForTestNoEmail"
    TRACER_ON = False

    class Config:
        env_file = '.env'


settings = Settings()
