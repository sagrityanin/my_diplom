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
        return f"User {params['email']} created"

    except Exception:
        return f"User {params['email']} NOT created"


def update_profile(request_dict: dict, payload: dict, user_id: str) -> dict:
    profile = {}
    print("request_dict", request_dict)
    print("payload", payload)
    print("user_id", user_id)
    if payload["Check_token"] is True and (payload["role"] == "admin" or payload["role"] == "superuser"):  # type: ignore
        profile["user_id"] = user_id
        user = Users.query.filter_by(id=user_id).first()
        logging.info(f"user id {user.id}")

        profile["login"] = user_settings.set_login(request_dict, user)
        profile["password"] = user_settings.set_password(request_dict, user)
        profile["role"] = user_settings.set_role(request_dict, user, payload)
        profile["is_active"] = user_settings.set_status(request_dict, user, payload)

    elif payload["Check_token"] == "time out":  # type: ignore
        profile["token"] = "time out"
    else:
        profile["token"] = "broken"
    logging.info(f"profile {profile}")
    return profile


def make_list(model_list: list[Users]):
    user_list = []
    for user in model_list:
        user_list.append({"user_id": str(user.id), "email": user.email})
    return user_list


def get_count_email_list(query_params: dict) -> Tuple[int, list[Users]]:
    count = Users.query.filter_by(email_notification=True, is_active=True).count()
    users_array = Users.query.order_by(Users.id.asc()).filter_by(email_notification=True,
                                                                 is_active=True).paginate(
        page=query_params["page_number"], per_page=query_params["page_size"])
    return count, users_array


def get_count_ws_list(query_params: dict) -> Tuple[int, list[Users]]:
    count = Users.query.filter_by(ws_notification=True, is_active=True).count()
    users_array = Users.query.order_by(Users.id.asc()).filter_by(ws_notification=True,
                                                                 is_active=True).paginate(
        page=query_params["page_number"], per_page=query_params["page_size"])
    return count, users_array


def get_users_notification_list(query_params: dict) -> dict:
    check_pages = check_page_params(query_params)
    if check_pages is not True:
        return check_pages  # type: ignore
    res = {}
    users_list = []
    if query_params["type_notification"] == "email_notification":
        count, users_array = get_count_email_list(query_params)
    elif query_params["type_notification"] == "ws_notification":
        count, users_array = get_count_ws_list(query_params)
    else:
        return {"type_notification": "wrong"}
    check_max_number = check_page_number(count, query_params)
    if check_max_number is not True:
        return check_max_number  # type: ignore
    for user in users_array.items:
        users_list.append({"user_id": str(user.id), "email": user.email})
    res["Total count page"] = math.ceil(count / query_params["page_size"])
    res["users"] = users_list  # type: ignore

    return res


def get_users_list(query_params: dict) -> dict:
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
    logging.info(user)
    profile["user_id"] = str(user.id)
    profile["email"] = user.email
    role = Roles.query.filter_by(id=user.role_id).first()
    profile["role"] = role.role
    profile["created_at"] = user.created_at
    profile["updated_at"] = str(user.updated_at)
    profile["is_active"] = user.is_active
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
    # current_token = token.TokenGet(payload)
    list_token["access_token"] = sjwt.gettoken.get_token(settings.JWT_KEY, settings.TTL_ACCESS_TOKEN,
                                                         **payload)
    payload["type"] = "refresh_token"
    # current_token = token.TokenGet(payload)
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
    for work_token in list_token:
        resp.headers[work_token] = list_token[work_token]
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
    query_params["type_notification"] = request.args.get("type_notification")
    logging.info(f"page params {query_params}")
    return query_params


def check_page_params(query_params: dict) -> Union[dict, bool]:
    if query_params["page_number"] <= 0 or query_params["page_size"] <= 0:
        return {"Page param": "wrong"}
    else:
        return True


def check_page_number(count: int, query_params: dict) -> Union[dict, bool]:
    if count == 0:
        return {"Found": "0 records"}
    if count < query_params["page_size"] * (query_params["page_number"] - 1):
        print("count", count)
        return {"Page number": "too big"}
    return True


def get_login_log_list(user_id: str, query_params: dict) -> dict:
    logging.info("get_log_list")
    check_pages = check_page_params(query_params)
    if check_pages is not True:
        return check_pages  # type: ignore
    res = {}
    if query_params["sort_field"] not in schemas.users_logs_sort_field_dict \
            or query_params["sort_order"] not in schemas.sort_order_list:
        res["sort params"] = "wrong"
        return res
    try:
        count = UsersLogs.query.filter(UsersLogs.user_id == user_id,
                                       UsersLogs.user_action == "success user login").count()
    except Exception as e:
        logging.info("Exception", e)
        return {"Request": "wrong request"}
    check_max_number = check_page_number(count, query_params)
    if check_max_number is not True:
        return check_max_number  # type: ignore
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


def get_user_email(user_id: str) -> dict:
    user = Users.query.filter_by(id=user_id).first()
    return {"User_email": user.email}
