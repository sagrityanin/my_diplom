import sjwt

from core.config import settings


def get_payload_sjwt(has_token):
    payload = sjwt.checktoken.get_payload(key=settings.JWT_KEY, token=has_token)
    print("payload", payload)
    return payload


def get_token(payload: dict):
    JWT_KEY = settings.JWT_KEY
    my_token = sjwt.gettoken.get_token(JWT_KEY, **payload)
    return my_token
