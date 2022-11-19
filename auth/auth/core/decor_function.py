from functools import wraps
from flask import jsonify
from flask import request
import sjwt
from core.config import settings

from core import utils  # type: ignore


def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            payload = utils.get_payload(request.headers["access_token"])
            if payload["role"] == "admin" or payload["role"] == "superuser":
                return fn(*args, **kwargs)
            return {"message": "Admin access required"}

        return decorator

    return wrapper


def admin_or_self_user_required(user_id):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            payload = utils.get_payload(request.headers["access_token"])
            if payload["role"] == "admin" or payload["role"] == "superuser" \
                    or payload["user_id"] == user_id:
                return fn(*args, **kwargs)
            return jsonify(msg="Admins or self only!"), 403

        return decorator

    return wrapper


def active_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            if request.headers.get("access_token") is None:
                return {"Token status": "not present"}
            payload = sjwt.checktoken.get_payload(key=settings.JWT_KEY,
                                                  token=request.headers.get("access_token"))
            if payload == "Token can broken":
                return "Token can broken"
            try:
                if payload["Check_token"] is True:
                    return fn(*args, **kwargs)
                return {"Token status": "time out or broken"}
            except TypeError:
                return {"Token status": "broken"}

        return decorator

    return wrapper


def check_admin_or_self_user(token: str, user_id: str):
    payload = utils.get_payload(token)
    print("payload", payload)
    if payload["role"] == "admin" or payload["role"] == "superuser" \
            or payload["user_id"] == user_id:
        return True
    return False


def check_self_user(token: str, user_id: str):
    payload = utils.get_payload(token)
    if payload["user_id"] == user_id:
        return True
    return False
