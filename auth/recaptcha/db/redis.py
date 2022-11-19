import redis
from core.config import settings

redis_conn = redis.Redis(
    host=settings.AUTH_REDIS,
    port=settings.AUTH_REDIS_PORT,
    db=2)
