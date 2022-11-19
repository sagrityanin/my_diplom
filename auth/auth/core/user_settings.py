import datetime
import logging
from typing import Optional
import uuid

from core import hash  # type: ignore
from core.config import settings  # type: ignore
from models.users import Users
from models.roles import Roles
from models.subscribtion import Subscribtion
from models.confirm_email import ConfirmEmail
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
        if (request_dict["role"] in settings.ROLES_FOR_ADMIN_EDIT and payload["role"] == "admin") \
                or payload["role"] == "superuser":
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
                (payload["role"] == "admin" or payload["role"] == "superuser"):
            user.is_active = request_dict["is_active"]
            db.session.commit()
            is_active = "has changed"
        else:
            is_active = "not changed"
    except Exception:
        is_active = "has not changed"
    return is_active


def set_login(request_dict: dict, user: Users) -> str:
    try:
        if len(request_dict["login"]) > 2:
            user.login = request_dict["login"]
            db.session.commit()
            login = "has changed"
        else:
            login = "not changed"
    except Exception:
        login = "can not changed"
    return login


def set_email_notification(request_dict: dict, user: Users) -> str:
    try:
        if request_dict["email_notification"] is not None:
            user.email_notification = request_dict["email_notification"]
            db.session.commit()
            email_notification = "email_notification has changed"
        else:
            email_notification = "email_notification not changed"
    except Exception:
        email_notification = "email_notification can not changed"
    return email_notification


def set_ws_notification(request_dict: dict, user: Users) -> str:
    try:
        if request_dict["ws_notification"] is not None:
            user.ws_notification = request_dict["ws_notification"]
            db.session.commit()
            ws_notification = "ws_notification has changed"
        else:
            ws_notification = "ws_notification not changed"
    except Exception:
        ws_notification = "ws_notification can not changed"
    return ws_notification


def confirm_email(confirm_id: str) -> Optional[str]:
    confirm_record = ConfirmEmail.query.filter_by(id=confirm_id).first()
    if confirm_record is None:
        return "Confirm record not exists"
    if confirm_record.exp_confirm_email < datetime.datetime.now():
        return "Confirm time out"
    user_id = confirm_record.user_id
    user = Users.query.filter_by(id=user_id).first()
    user.confirm_email_status = True
    db.session.add(user)
    db.session.delete(confirm_record)
    db.session.commit()
    logging.info(f"User {user.email} confirm email")
    logging.info(f"Confirm record {confirm_id} deleted")
    return f"{user.email} confirm email"


def check_user_subscribtion(user_id):
    try:
        if uuid.UUID(user_id):
            pass
    except Exception as e:
        logging.info(e)
        return False
    now = datetime.datetime.now()
    user_subsribtion = Subscribtion.query.filter(Subscribtion.user_id == uuid.UUID(user_id),
                                                 Subscribtion.payment_status == "payment_completed",
                                                 Subscribtion.start_subscribtion < now,
                                                 Subscribtion.subscribtion_expiration_datetime > now).first()
    if user_subsribtion is None:
        logging.info(f"User {user_id} has not subscribtion")
        return False
    logging.info(f"User {user_id} has subscribtion")
    return True
