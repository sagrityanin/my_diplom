import logging
from flask_restx import Resource, fields, Namespace  # type: ignore
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden

from flask import request

from models.users import Users
from db.redis import redis_conn
from core.config import settings  # type: ignore
from core import hash, utils, schemas, decor_function  # type: ignore
from core.rate_limiter import limiter  # type: ignore
from payload_get import token_payload  # type: ignore
from core.logger import file_handler  # type: ignore

authorizations = schemas.authorizations
api = Namespace("user", description="API for work with users", authorizations=authorizations,
                url_prefix="user")
api.logger.addHandler(file_handler)

model_response_400_401_403_404_base = api.model("ErrorBase", schemas.model_response_400_401_403_404_base)
model_user_login = api.model("UserLogin", schemas.model_user_login)
model_response_users_profile = api.model("ProfileResponse", schemas.model_response_users_profile)
model_new_user = api.model("new_user", schemas.model_new_user)
model_response_users_id_profile_response_get = api.model("UserIdProfileResponse",
                                                         schemas.model_response_users_id_profile_response_get)
model_response_users_id_profile_response_post = api.model("UserIdProfileResponse",
                                                          schemas.model_response_users_id_profile_response_post)
model_response_users_list_nested_user = api.model("UserForUsersListResponse",
                                                  schemas.model_response_users_list_nested_user_row)
model_profile = api.model("Profile", schemas.model_profile)
model_response_users_list_nested_user = api.model("UserForUsersListResponse",
                                                  schemas.model_response_users_list_nested_user_row)
model_response_users_list_row = {
    "Total count page": fields.Integer(description="Pages in total"),
    "Users list": fields.String(description="Result"),
    "users": fields.List(fields.Nested(model_response_users_list_nested_user))
}
model_response_users_list = api.model("UsersListResponse", model_response_users_list_row)
model_notification_users_list = api.model("NotificationUsersList", model_response_users_list_row)


@api.route("/login")
class Login(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_USERS, override_defaults=False)]

    @api.doc(
        description="Path your email and passwworn to get your refresh and access tokens\
                        via headers 'access_token' and 'refresh_token' in response"
    )
    @api.response(200, 'Success', headers={"access_token": "JWT", "refresh_token": "JWT"})
    @api.response(401, 'Unauthorized', model_response_400_401_403_404_base)
    @api.response(404, 'Not found', model_response_400_401_403_404_base)
    @api.expect(model_user_login)
    def post(self):
        """
        Login to the service
        """
        current_user = request.json
        api.logger.info(f"current_user {current_user}")
        headers_user = request.headers
        user_email = current_user["user_email"]
        password = current_user['password']
        try:
            user = Users.query.filter_by(email=user_email).first()
            logging.info(f"user {user, user.id, user.created_at}")
            if user is None:
                api.logger.info(f"User {user_email} not found")
                raise BadRequest(f"User {user_email} not found")
        except Exception:
            api.logger.info(f"User {user_email} not found")
            raise BadRequest(f"User {user_email} not found")
        user_log_agent = headers_user["User-Agent"]
        hash_password = hash.get_hash(password, user.created_at)
        if user.is_active is False:
            raise Unauthorized(f"user {user_email} not active")
        if user.password == hash_password:
            utils.write_log(user.id, user_log_agent, "success user login")
            api.logger.info(f"Admin {user.email} id {user.id} success login")
            return utils.create_load_tokens(user_email, user.id, user.role_id)

        utils.write_log(user.id, user_log_agent, "unsuccess user login")
        raise Unauthorized("Username password broken")


@api.route("/logout")
class Logout(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_USERS, override_defaults=False)]

    @api.doc(
        responses={200: "OK"},
        description="Path your refresh token in header 'refresh_token', and access token in 'access_token' \
                        header, they will be unusable after logout"
    )
    @api.response(400, 'Bad Request', model_response_400_401_403_404_base)
    @api.response(401, 'Unauthorized', model_response_400_401_403_404_base)
    @api.doc(security=("access_token", "refresh_token"))
    def get(self):
        """
        Logout from service
        """
        res = {}
        has_refresh_token = request.headers.get("refresh_token")
        if has_refresh_token is None:
            raise BadRequest("Need refresh token")
        refresh_payload = token_payload.get_payload_sjwt(has_refresh_token)
        res["user_email"] = refresh_payload["user_email"]
        if refresh_payload["type"] == "refresh_token" and refresh_payload["Check_token"] is True:
            refresh_key = refresh_payload["user_id"] + "_refresh_token"
            refresh_key_value = refresh_payload["exp"]
            redis_conn.set(refresh_key, refresh_key_value, settings.TTL_REFRESH_TOKEN)
        else:
            raise Unauthorized("Refresh token broken")
        res["status"] = "logout"
        try:
            utils.write_log(refresh_payload["user_id"], request.headers.get("User-Agent"), "success user logout")
        except Exception:
            logging.info(f"ERROR write log {refresh_payload['user_id']}, {request.headers.get('User-Agent')}")
        api.logger.info(res)
        return res


@api.route("/new-user")
class UserCheck(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_USERS, override_defaults=False)]

    @api.doc(
        responses={200: "OK"},
        description="New user will be created with default role = 'unsubcriber'"
    )
    @api.response(400, 'Bad Request', model_response_400_401_403_404_base)
    @api.expect(model_new_user)
    def post(self):
        """
        Create new user
        """
        user_params = request.json
        api.logger.info(user_params)
        user = Users.query.filter_by(email=user_params["email"]).first()
        if user is not None:
            api.logger.info(f"User_name {user_params['email']} is busy")
            raise BadRequest(f"User_name {user_params['email']} is busy")
        res = utils.create_user(user_params)
        api.logger.info(res)
        return res


@api.route("/<user_id>/profile/")
class Admin(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_USERS, override_defaults=False)]

    @api.doc(
        params={'user_id': 'UUID'},
        description="Path access token via header 'access_token' to recive user profile."
    )
    @api.response(200, 'Success', model_response_users_id_profile_response_get)
    @api.response(401, 'Unauthorized', model_response_400_401_403_404_base)
    @api.response(403, 'Forbidden', model_response_400_401_403_404_base)
    @api.doc(security="access_token")
    @decor_function.admin_required()
    @decor_function.active_required()
    def get(self, user_id):
        """
        User profile
        """
        profile = {}
        try:
            if decor_function.check_admin_or_self_user(request.headers.get("access_token"), user_id):
                profile = utils.make_user_profile(user_id, profile)
                api.logger.info(profile)
                return profile
            api.logger.info("Token broken or have not permitins")
            raise Forbidden("Token broken or have not permitins")
        except Exception:
            api.logger.info("Token broken")
            raise Unauthorized()

    @api.doc(
        params={'user_id': 'UUID'},
        description="Path access token via header 'access_token' to edit user profile."
    )
    @api.response(200, 'Success', model_response_users_id_profile_response_post)
    @api.response(400, 'Bad Request', model_response_400_401_403_404_base)
    @api.response(404, 'Not found', model_response_400_401_403_404_base)
    @api.doc(security="access_token")
    @api.expect(model_profile)
    @decor_function.admin_required()
    @decor_function.active_required()
    def patch(self, user_id):
        """
        Edit user profile
        """
        try:
            payload = token_payload.get_payload_sjwt(request.headers.get("access_token"))
            api.logger.info(f"payload in post profile {payload}")
            request_dict = request.json
            api.logger.info(f"request_dict {request_dict}")
            profile = utils.update_profile(request_dict, payload, user_id)
            utils.write_log(payload["user_id"], request.headers.get('User-Agent'), "update user profile by admin")
        except Exception:
            api.logger.info("User is not exists")
            raise BadRequest("User is not exists")
        api.logger.info(f"Admin {payload['user_id']} {profile}")
        return profile


@api.route("/users-list")
class ListUsers(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_USERS, override_defaults=False)]

    @api.doc(
        description="Path access token via header 'access_token' to recive list of the users"
    )
    @api.param("page_number", "int > 0", required=True)
    @api.param("page_size", "int > 0", required=True)
    @api.param("sort_field", "email or login", required=True)
    @api.param("sort_order", "asc or desc", required=True)
    @api.response(200, 'Success', model_response_users_list)
    @api.response(400, 'Bad Request', model_response_400_401_403_404_base)
    @api.response(401, 'Unauthorized', model_response_400_401_403_404_base)
    @api.response(403, 'Forbidden', model_response_400_401_403_404_base)
    @api.doc(security="access_token")
    @decor_function.active_required()
    @decor_function.admin_required()
    def get(self):
        """
        List of users
        """
        try:
            params = utils.get_params(request)
        except Exception:
            api.logger.info("Page is not int or not exists")
            raise BadRequest("Page is not int or not exists")
        try:
            res = utils.get_users_list(params)
        except Exception:
            api.logger.info("token broken")
            raise Unauthorized("token broken")
        api.logger.info(res)
        return res


@api.route("/users-notification-list/")
class ListNotificationUsers(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_USERS, override_defaults=False)]

    @api.doc(
        description="Path access token via header 'access_token' to recive list of the users"
    )
    # @api.response(200, 'Success', model_response_users_list)
    @api.response(400, 'Bad Request', model_response_400_401_403_404_base)
    @api.response(401, 'Unauthorized', model_response_400_401_403_404_base)
    @api.response(403, 'Forbidden', model_response_400_401_403_404_base)
    @api.doc(security="access_token")
    @api.param("page_number", "int > 0", required=True)
    @api.param("page_size", "int > 0", required=True)
    @api.param("type_notification", "email_notification or ws_notification", required=True)
    @decor_function.active_required()
    @decor_function.admin_required()
    def get(self):
        """
        List of users fot notification
        """
        try:
            params = utils.get_params(request)
        except Exception:
            api.logger.info("Page is not int or not exists")
            raise BadRequest("Page is not int or not exists")

        try:
            res = utils.get_users_notification_list(params)
        except Exception as e1:
            api.logger.info(e1)
            raise Unauthorized("token may be broken")
        if res is None:
            api.logger.info("Incorrect type_notification, please select email_notification or ws_notification")
            raise BadRequest("Incorrect type_notification, please select email_notification or ws_notification")
        api.logger.info(res)
        return res


@api.route("/user-login-logs/<user_id>")
class UserLogs(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_USERS, override_defaults=False)]

    @api.doc(
        description="Path access token via header 'access_token' to recive list of the user logs"
    )
    @api.param("page_number", "int > 0", required=True)
    @api.param("page_size", "int > 0", required=True)
    @api.param("sort_field", "user_agent or created_at", required=True)
    @api.param("sort_order", "asc or desc", required=True)
    @api.response(200, 'Success', model_response_users_list)
    @api.response(401, 'Unauthorized', model_response_400_401_403_404_base)
    @api.response(403, 'Forbidden', model_response_400_401_403_404_base)
    @api.doc(security="access_token")
    @decor_function.active_required()
    def get(self, user_id):
        """
        List of user logs
        """
        try:
            params = utils.get_params(request)
        except Exception:
            api.logger.info("Page is not int or nor exists")
            raise BadRequest("Page is not int or nor exists")
        try:
            if decor_function.check_admin_or_self_user(request.headers["access_token"], user_id):
                res = utils.get_login_log_list(user_id, params)
                api.logger.info(res)
                return res
            api.logger.info("Token ")
            raise Forbidden("Token ")
        except Exception:
            api.logger.info("token broken")
            raise Unauthorized("token broken")


@api.route("/user-get-email/")
class UserEmail(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_USERS, override_defaults=False)]

    @api.doc(
        description="Path access token via header 'access_token' and user id via get param \
                     to recive user email"
    )
    @api.response(400, 'Bad Request', model_response_400_401_403_404_base)
    @api.response(401, 'Unauthorized', model_response_400_401_403_404_base)
    @api.response(403, 'Forbidden', model_response_400_401_403_404_base)
    @api.doc(security="access_token")
    @api.param("user_id", required=True)
    @decor_function.active_required()
    @decor_function.admin_required()
    def get(self):
        """
        User email
        """
        try:
            user_id = request.args.get("user_id")
        except Exception:
            api.logger.info("Need user_id")
            raise BadRequest("Need user_id")
        try:
            res = utils.get_user_email(user_id)
        except Exception:
            api.logger.info("Bad user_id")
            raise Unauthorized("Bad user_id")
        api.logger.info(f"Get user email {res['User_email']}")
        return res
