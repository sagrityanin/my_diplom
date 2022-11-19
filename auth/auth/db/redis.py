import redis  # type: ignore
from core.config import settings  # type: ignore

redis_conn = redis.Redis(
    host=settings.AUTH_REDIS,
    port=settings.AUTH_REDIS_PORT,
    db=3)
