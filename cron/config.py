from pydantic import BaseSettings


class Settings(BaseSettings):
    AUTH_POSTGRES_HOST: str
    AUTH_POSTGRES_PORT: int
    AUTH_POSTGRES_DB: str
    AUTH_POSTGRES_USER: str
    AUTH_POSTGRES_PASSWORD: str
    JWT_KEY: str
    REMINDER_STEP = 5
    PAUSE = 24 * 60 * 60
    MONGO_DSN = "mongodb://mongo:27017/"
    MONGO_DB = "films_summary"
    MONGO_NOTIFICATION_COLLECTION = "email_notification"
    NOTIFICATION_QUEUE = "email.notification"
    REBBITMQ_HOST = "rabbitmq"
    REBBITMQ_PORT = 5672
    RENEWAL_INTERVAL = 1 # in minutes
    RENEWAL_STEP = 5


    class Config:
        env_file = '.env'


settings = Settings()
