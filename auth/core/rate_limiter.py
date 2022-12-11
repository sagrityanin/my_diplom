from core.application import app  # type: ignore
from core.config import settings  # type: ignore
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=settings.RATE_LIMIT_DEFAULT_SEC,
    storage_uri=f"redis://{settings.AUTH_REDIS}:{settings.AUTH_REDIS_PORT}?db=1",
    strategy="fixed-window",
)
