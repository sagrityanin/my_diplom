import sjwt
import logging
from core.config import settings


def get_payload_sjwt(has_token):
    payload = sjwt.checktoken.get_payload(key=settings.JWT_KEY, token=has_token)
    logging.info("payload", payload)
    return payload


def get_token(payload: dict):
    my_token = sjwt.gettoken.get_token(settings.JWT_KEY, **payload)
    return my_token
