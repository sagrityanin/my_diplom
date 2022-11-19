import uuid
from datetime import datetime, timedelta
import logging
from functools import wraps
import math
from flask import request, Response  # type: ignore
import requests
import sjwt  # type: ignore
from typing import Optional, Any

from models.confirm_email import ConfirmEmail
from models.users import Users
from models.roles import Roles
from models.users_logs import UsersLogs
from core import hash, schemas, user_settings  # type: ignore
from core.config import settings  # type: ignore
from db.redis import redis_conn  # type: ignore
from db.postgres import db  # type: ignore
from db.rabbitmq import queue


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'access_token' in request.headers:
            token = request.headers.get('access_token')

        if not token:
            return {'message': 'Token is missing'}, 401

        return f(*args, **kwargs)

    return decorated


def get_shot_url(long_url: str) -> str:
    api_url = settings.TINYURL
    params = {"api_token": settings.TINYURL_TOKEN}
    date = {"url": long_url, "domain": settings.TINYURL_DOMAIN}
    res = requests.post(api_url, params=params, json=date).json()
    logging.info(f"get shot url {res['data']['tiny_url']}")
    return res["data"]["tiny_url"]


def send_request(email, user_id, confirm_email_id, message):
    payload = {"user_email": email, "user_id": user_id, "role": "admin", "type": "access_token"}
    access_token = sjwt.gettoken.get_token(settings.JWT_KEY, **payload)
    url = f"{settings.NOTIFICATION_URL}/notifications/api/v1/single-notification/"
    body = {
        "notification_id": confirm_email_id,
        "user_id": user_id,
        "message": message,
        "subject": "Confirm email in cinema"
    }
    params = {"type_notification": "email_notification"}
    headers = {"access_token": access_token}
    try:
        res = requests.post(url, json=body, params=params, headers=headers).json()
        return res
    except Exception as e:
        return e


def send_welcome_email(email: str, user_id: str) -> Optional[str]:
    confirm_email_id = str(uuid.uuid4())
    dt = datetime.now() + timedelta(hours=settings.TTL_CONFIRM_EMAIL)
    confirm_email = ConfirmEmail(id=confirm_email_id, user_id=user_id, exp_confirm_email=dt)
    db.session.add(confirm_email)
    db.session.commit()
    logging.info(f"Confirm_email id {confirm_email_id} email: {email} has created")
    if settings.TEST_DOMEN in email:
        logging.info(f"Welcome email tested to {email}")
        return "Test email fack sended"
    confirm_url = f"https://pycinema.ru/auth/api/v1/users/confirm-email/{confirm_email_id}"
    shot_url = get_shot_url(confirm_url)
    message = f"Welcome to site our cinema. To comfirm email go {shot_url}"
    # Chice send email by http-request or put to queue in rabbitmq
    res = queue.make_message(confirm_email_id, email, message, "Confirm email in cinema")
    # res = send_request(email, user_id, confirm_email_id, message)

    logging.info(res)
    return res


def create_user(params: dict) -> str:
    time_created = str(datetime.now())
    roles = Roles.query.filter_by(role='unsubscriber').first()
    hash_password = hash.get_hash(params["password"], time_created)
    try:
        new_user = Users(password=hash_password, email=params["email"],
                         created_at=time_created, role_id=roles.id,
                         is_active=True)
        if len(params["login"]) > 2:
            new_user.login = params["login"]
        db.session.add(new_user)
        db.session.commit()
        res = send_welcome_email(params["email"], str(new_user.id))
        return f"User {params['email']} created, {res}"

    except Exception:
        return f"User {params['email']} NOT created"


def get_payload(has_token: str) -> dict:
    payload = sjwt.checktoken.get_payload(key=settings.JWT_KEY, token=has_token)
    return payload


def update_profile(request_dict: dict, payload: dict, user_id: str) -> dict:
    profile = {}
    token_user = Users.query.filter_by(id=payload["user_id"]).first()
    try:
        if token_user.is_active is False:
            profile[f"user {payload['user_email']}"] = "is not active"
            return profile
    except Exception:
        return {"status": "user_id in token is broken"}
    if payload["Check_token"] is True and payload["user_id"] == user_id:
        profile["user_id"] = user_id
        user = Users.query.filter_by(id=user_id).first()
        logging.info(f"user id {user.id}")

        profile["login"] = user_settings.set_login(request_dict, user)
        profile["password"] = user_settings.set_password(request_dict, user)
        profile["role"] = user_settings.set_role(request_dict, user, payload)
        profile["is_active"] = user_settings.set_status(request_dict, user, payload)
        profile["email_notification"] = user_settings.set_email_notification(request_dict, user)
        profile["ws_notification"] = user_settings.set_ws_notification(request_dict, user)

    elif payload["Check_token"] == "time out":
        profile["token"] = "time out"
    else:
        profile["token"] = "broken"
    logging.info(f"profile {profile}")
    return profile


def get_users_notification_list(argument: str) -> Optional[list]:
    print("argument", argument)
    if argument == "email_notification":
        users_list = Users.query.filter_by(email_notification=True)
    elif argument == "ws_notification":
        users_list = Users.query.filter_by(ws_notification=True)
    else:
        users_list = None
    return users_list


def get_users_list(query_params: dict) -> dict[str, Any]:
    res = {}
    if query_params["page_number"] <= 0 or query_params["page_size"] <= 0:
        res["Page param"] = "wrong"
        return res
    if query_params["sort_field"] not in schemas.users_sort_field_dict \
            or query_params["sort_order"] not in schemas.sort_order_list:
        res["sort params"] = "wrong"
        return res
    count = Users.query.count()
    if count < query_params["page_size"] * (query_params["page_number"] - 1):
        res["Page number"] = "too big"
        return res
    res["Total count page"] = math.ceil(count / query_params["page_size"])  # type: ignore
    res["Users list"] = "has done"
    logging.info(f"res_query {query_params['page_number']}, {query_params['page_size']}")
    logging.info(f"sort field {query_params['sort_field']}")
    if query_params["sort_order"] == "asc":
        user_array = Users.query.order_by(schemas.users_sort_field_dict[query_params["sort_field"]].asc()). \
            paginate(page=query_params["page_number"], per_page=query_params["page_size"])
    else:
        user_array = Users.query.order_by(schemas.users_sort_field_dict[query_params["sort_field"]].desc()). \
            paginate(page=query_params["page_number"], per_page=query_params["page_size"])

    logging.info(f"user_array {user_array}")
    logging.info(f"user_array_items {user_array.items}")
    res["users"] = []  # type: ignore
    for user in user_array.items:
        logging.info(f"user {user}")
        role = Roles.query.filter_by(id=user.role_id).first()
        res["users"].append({"email": user.email,  # type: ignore
                             "id": str(user.id),
                             "role": role.role,
                             "login": user.login})
    return res


def make_user_profile(user_id: str, profile: dict) -> dict:
    user = Users.query.filter_by(id=user_id).first()
    profile["user_id"] = str(user.id)
    profile["email"] = user.email
    role = Roles.query.filter_by(id=user.role_id).first()
    profile["role"] = role.role
    profile["created_at"] = user.created_at
    profile["updated_at"] = str(user.updated_at)
    profile["is_active"] = user.is_active
    profile["email_notification"] = user.email_notification
    profile["ws_notification"] = user.ws_notification
    return profile


def write_log(user_id: str, user_log_agent: str, action: str) -> None:
    try:
        user_log = UsersLogs(user_id=user_id, user_agent=user_log_agent, user_action=action)
        db.session.add(user_log)
        db.session.commit()
    except Exception:
        logging.info("Can not write log")


def create_two_token(payload: dict) -> dict:
    list_token = {}
    payload["type"] = "access_token"
    list_token["access_token"] = sjwt.gettoken.get_token(settings.JWT_KEY, settings.TTL_ACCESS_TOKEN,
                                                         **payload)
    payload["type"] = "refresh_token"
    list_token["refresh_token"] = sjwt.gettoken.get_token(settings.JWT_KEY, settings.TTL_REFRESH_TOKEN,
                                                          **payload)
    return list_token


def create_load_tokens(user_email, user_id, user_role_id):
    resp = Response("Login succesful")
    payload = {}
    payload["user_email"] = user_email
    payload["user_id"] = str(user_id)
    role = Roles.query.filter_by(id=user_role_id).first()
    payload["role"] = role.role
    list_token = create_two_token(payload)
    for token in list_token:
        resp.headers[token] = list_token[token]
    return resp


def get_token_from_redis(payload: dict) -> bool:
    refresh_token_label = payload["user_id"] + "_refresh_token"
    blok_token_time_encode = redis_conn.get(refresh_token_label)
    if blok_token_time_encode is None:
        return False
    blok_token_time = blok_token_time_encode.decode('utf-8')
    if float(blok_token_time) >= payload["exp"]:
        return True
    return False


def get_params(request) -> dict:
    query_params = {}
    query_params["page_size"] = int(request.args.get("page_size"))
    query_params["page_number"] = int(request.args.get("page_number"))
    query_params["sort_field"] = request.args.get("sort_field")
    query_params["sort_order"] = request.args.get("sort_order")
    logging.info(f"page params {query_params}")
    return query_params


def get_login_log_list(user_id: str, query_params: dict) -> dict[str, Any]:
    logging.info("get_log_list")
    res = {}
    logging.info(f"query_params {query_params}")
    if query_params["page_number"] <= 0 or query_params["page_size"] <= 0:
        res["Page param"] = "wrong"
        return res
    if query_params["sort_field"] not in schemas.users_logs_sort_field_dict \
            or query_params["sort_order"] not in schemas.sort_order_list:
        res["sort params"] = "wrong"
        return res
    logging.info("check page params")
    count = UsersLogs.query.filter(UsersLogs.user_id == user_id, UsersLogs.user_action == "success user login").count()
    logging.info(f"count {count}")
    if count < query_params["page_size"] * (query_params["page_number"] - 1):
        res["Page number"] = "too big"
        return res
    res["Total count page"] = math.ceil(count / query_params["page_size"])  # type: ignore
    res["User logs list"] = "has done"
    logging.info(f"res_query {query_params['page_number']}, {query_params['page_size']}")
    logging.info(f"sort field {query_params}")
    if query_params["sort_order"] == "asc":
        logs_array = UsersLogs.query.filter(UsersLogs.user_id == user_id,
                                            UsersLogs.user_action == "success user login"). \
            order_by(schemas.users_logs_sort_field_dict[query_params["sort_field"]].asc()). \
            paginate(page=query_params["page_number"], per_page=query_params["page_size"])
    else:
        logs_array = UsersLogs.query.filter(UsersLogs.user_id == user_id,
                                            UsersLogs.user_action == "success user login"). \
            order_by(schemas.users_logs_sort_field_dict[query_params["sort_field"]].desc()). \
            paginate(page=query_params["page_number"], per_page=query_params["page_size"])
    logging.info(f"logs_array {logs_array}")
    logging.info(f"logs_array_items {logs_array.items}")
    res["users"] = []  # type: ignore
    for log in logs_array.items:
        logging.info(f"user {log}")
        user = Users.query.filter_by(id=log.user_id).first()
        res["users"].append({"email": user.email,  # type: ignore
                             "id": str(log.user_id),
                             "action": log.user_action,
                             "Data time": str(log.created_at),
                             "user_agent": log.user_agent,
                             })
    return res
