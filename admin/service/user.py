import logging
import math
from datetime import datetime
from functools import wraps
from typing import Tuple, Union
from flask import request

from core import schemas  # type: ignore
from service import hash, user_settings  # type: ignore
from db.postgres import db
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


class UserClass:
    def __init__(self):
        pass

    @classmethod
    def create_user(cls, params: dict) -> str:
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

    @classmethod
    def update_profile(cls, request_dict: dict, payload: dict, user_id: str) -> dict:
        profile = {}
        print("request_dict", request_dict)
        print("payload", payload)
        print("user_id", user_id)
        if payload["Check_token"] is True and (
                payload["role"] == "admin" or payload["role"] == "superuser"):  # type: ignore
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

    @classmethod
    def make_list(cls, model_list: list[Users]):
        user_list = []
        for user in model_list:
            user_list.append({"user_id": str(user.id), "email": user.email})
        return user_list

    @classmethod
    def get_count_email_list(cls, query_params: dict) -> Tuple[int, list[Users]]:
        count = Users.query.filter_by(email_notification=True, is_active=True).count()
        users_array = Users.query.order_by(Users.id.asc()).filter_by(email_notification=True,
                                                                     is_active=True).paginate(
            page=query_params["page_number"], per_page=query_params["page_size"])
        return count, users_array

    @classmethod
    def get_count_ws_list(cls, query_params: dict) -> Tuple[int, list[Users]]:
        count = Users.query.filter_by(ws_notification=True, is_active=True).count()
        users_array = Users.query.order_by(Users.id.asc()).filter_by(ws_notification=True,
                                                                     is_active=True).paginate(
            page=query_params["page_number"], per_page=query_params["page_size"])
        return count, users_array

    @classmethod
    def get_users_notification_list(cls, query_params: dict) -> dict:
        check_pages = UserClass.check_page_params(query_params)
        if check_pages is not True:
            return check_pages  # type: ignore
        res = {}
        users_list = []
        if query_params["type_notification"] == "email_notification":
            count, users_array = UserClass().get_count_email_list(query_params)
        elif query_params["type_notification"] == "ws_notification":
            count, users_array = UserClass().get_count_ws_list(query_params)
        else:
            return {"type_notification": "wrong"}
        check_max_number = UserClass.check_page_number(count, query_params)
        if check_max_number is not True:
            return check_max_number  # type: ignore
        for user in users_array.items:
            users_list.append({"user_id": str(user.id), "email": user.email})
        res["Total count page"] = math.ceil(count / query_params["page_size"])
        res["users"] = users_list  # type: ignore

        return res

    @classmethod
    def get_users_list(cls, query_params: dict) -> dict:
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

    @classmethod
    def make_user_profile(cls, user_id: str, profile: dict) -> dict:
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

    @classmethod
    def write_log(cls, user_id: str, user_log_agent: str, action: str) -> None:
        try:
            user_log = UsersLogs(user_id=user_id, user_agent=user_log_agent, user_action=action)
            db.session.add(user_log)
            db.session.commit()
        except Exception:
            logging.info("Can not write log")

    @classmethod
    def get_params(cls, request) -> dict:
        query_params = {}
        query_params["page_size"] = int(request.args.get("page_size"))
        query_params["page_number"] = int(request.args.get("page_number"))
        query_params["sort_field"] = request.args.get("sort_field")
        query_params["sort_order"] = request.args.get("sort_order")
        query_params["type_notification"] = request.args.get("type_notification")
        logging.info(f"page params {query_params}")
        return query_params

    @classmethod
    def check_page_params(cls, query_params: dict) -> Union[dict, bool]:
        if query_params["page_number"] <= 0 or query_params["page_size"] <= 0:
            return {"Page param": "wrong"}
        else:
            return True

    @classmethod
    def check_page_number(cls, count: int, query_params: dict) -> Union[dict, bool]:
        if count == 0:
            return {"Found": "0 records"}
        if count < query_params["page_size"] * (query_params["page_number"] - 1):
            logging.info("count", count)
            return {"Page number": "too big"}
        return True

    @classmethod
    def get_login_log_list(cls, user_id: str, query_params: dict) -> dict:
        logging.info("get_log_list")
        check_pages = UserClass().check_page_params(query_params)
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
        check_max_number = UserClass().check_page_number(count, query_params)
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

    @classmethod
    def get_user_email(cls, user_id: str) -> dict:
        user = Users.query.filter_by(id=user_id).first()
        return {"User_email": user.email}
