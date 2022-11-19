import logging

from core import hash  # type: ignore
from core.config import settings  # type: ignore
from models.users import Users
from models.roles import Roles
from db.postgres import db


def set_password(request_dict: dict, user: Users) -> str:
    try:
        if len(request_dict["password"]) > 3:
            new_password = hash.get_hash(request_dict["password"], user.created_at)
            user.password = new_password
            user.ext_auth_source_id = None
            db.session.commit()
            password = "has changed"
        else:
            password = "not changed"
    except Exception:
        password = "can not changed"
    return password


def set_role(request_dict: dict, user: Users, payload: dict) -> str:
    try:
        if request_dict["role"] in settings.ROLES_FOR_ADMIN_EDIT and \
                (payload["role"] == "admin" or payload["role"] == "superuser"):  # type: ignore
            role = Roles.query.filter_by(role=request_dict["role"]).first()
            user.role_id = role.id
            db.session.commit()
            role = "has changed"
        else:
            role = "not changed"
    except Exception:
        role = "can not changed"
    return role


def set_status(request_dict: dict, user: Users, payload: dict) -> str:
    try:
        if request_dict["is_active"] is not None and \
                (payload["role"] == "admin" or payload["role"] == "superuser"):  # type: ignore
            user.is_active = request_dict["is_active"]
            db.session.commit()
            is_active = "has changed"
        else:
            is_active = "not changed"
    except Exception:
        is_active = "has not changed"
    return is_active


def set_login(request_dict: dict, user: Users) -> str:
    logging.info(f"set login user {user}")
    logging.info((f"request dict in set login {request_dict}"))
    try:
        if len(request_dict["login"]) > 2:
            logging.info(f"user login {user.login}")
            set_user = Users.query.filter_by(id=user.id).first()
            set_user.login = request_dict["login"]
            logging.info(set_user.login)
            db.session.add(set_user)
            logging.info("add user")
            db.session.commit()
            login = "has changed"
        else:
            login = "not changed"
    except Exception:
        login = "can not changed"
    return login
