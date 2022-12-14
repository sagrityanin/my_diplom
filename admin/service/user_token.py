import logging
import math
from datetime import datetime
from functools import wraps
from typing import Tuple, Union

import sjwt
from core import schemas  # type: ignore
from service import hash, user_settings  # type: ignore
from core.config import settings
from db.postgres import db
from db.redis import redis_conn
from flask import Response, request
from models.roles import Roles
from models.users import Users
from models.users_logs import UsersLogs


class TokenClass:
    def __init__(self):
        pass

    @classmethod
    def create_load_tokens(cls, user_email, user_id, user_role_id):
        resp = Response("Login succesful")
        payload = {}
        payload["user_email"] = user_email
        payload["user_id"] = str(user_id)
        role = Roles.query.filter_by(id=user_role_id).first()
        payload["role"] = role.role
        list_token = TokenClass().create_two_token(payload)
        for work_token in list_token:
            resp.headers[work_token] = list_token[work_token]
        return resp

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
