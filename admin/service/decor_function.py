import logging
from functools import wraps
from flask import jsonify, request
from core.config import settings
import sjwt

def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            if request.headers.get("access_token") is None:
                return {"Token status": "not present"}
            payload = sjwt.checktoken.get_payload(key=settings.JWT_KEY, token=request.headers["access_token"])
            if payload["role"] == "admin" or payload["role"] == "superuser":
                return fn(*args, **kwargs)
            return {"message": "Admin access required"}

        return decorator

    return wrapper


def admin_or_self_user_required(user_id):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            if request.headers.get("access_token") is None:
                return {"Token status": "not present"}
            payload = sjwt.checktoken.get_payload(key=settings.JWT_KEY, token=request.headers["access_token"])
            try:
                if payload["role"] == "admin" or payload["role"] == "superuser" \
                        or payload["user_id"] == user_id:
                    return fn(*args, **kwargs)
                return jsonify(msg="Admins or self only!"), 403
            except Exception:
                return jsonify(msg="Admins or self only!"), 403

        return decorator

    return wrapper


def active_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            if request.headers.get("access_token") is None:
                return {"Token status": "not present"}
            payload = sjwt.checktoken.get_payload(key=settings.JWT_KEY, token=request.headers["access_token"])
            logging.info(f"payload in active_required {payload}")
            try:
                if payload["Check_token"] is True:
                    logging.info(f"Check token in active required {payload['Check_token']}")
                    return fn(*args, **kwargs)
                return {"Token status": "time out or broken"}
            except TypeError:
                return {"Token status": "broken"}

        return decorator

    return wrapper


def check_admin_or_self_user(token: str, user_id: str):
    payload = sjwt.checktoken.get_payload(key=settings.JWT_KEY, token=token)
    logging.info(f"payload in admin_or_self {payload}")
    try:
        if payload["role"] == "admin" or payload["role"] == "superuser"\
                or payload["user_id"] == user_id:
            logging.info("conditions in admin_or_self true")
            return True
        return False
    except Exception:
        return False
