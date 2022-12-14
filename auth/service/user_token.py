import logging
import math
import uuid
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Optional

import requests
import sjwt  # type: ignore
from core import hash, schemas, user_settings  # type: ignore
from core.config import settings  # type: ignore
from db.postgres import db  # type: ignore
from db.rabbitmq import queue
from db.redis import redis_conn  # type: ignore
from flask import Response, request  # type: ignore
from models.confirm_email import ConfirmEmail
from models.roles import Roles
from models.users import Users
from models.users_logs import UsersLogs





class TokenClass:
    def __init__(self):
        pass

    @classmethod
    def token_required(cls, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = None
            if 'access_token' in request.headers:
                token = request.headers.get('access_token')
            if not token:
                return {'message': 'Token is missing'}, 401
            return f(*args, **kwargs)

        return decorated

    @classmethod
    def create_two_token(cls, payload: dict) -> dict:
        list_token = {}
        payload["type"] = "access_token"
        list_token["access_token"] = sjwt.gettoken.get_token(settings.JWT_KEY, settings.TTL_ACCESS_TOKEN,
                                                             **payload)

        payload["type"] = "refresh_token"
        list_token["refresh_token"] = sjwt.gettoken.get_token(settings.JWT_KEY, settings.TTL_REFRESH_TOKEN,
                                                              **payload)
        return list_token

    @classmethod
    def get_token_from_redis(cls, payload: dict) -> bool:
        refresh_token_label = payload["user_id"] + "_refresh_token"
        blok_token_time_encode = redis_conn.get(refresh_token_label)
        if blok_token_time_encode is None:
            return False
        blok_token_time = blok_token_time_encode.decode('utf-8')
        if float(blok_token_time) >= payload["exp"]:
            return True
        return False