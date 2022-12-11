import logging

import sjwt
from core import (decor_function, hash, schemas, user_settings,  # type: ignore
                  utils)
from core.config import settings  # type: ignore
from core.logger import file_handler  # type: ignore
from core.rate_limiter import limiter  # type: ignore
from core.user import user
from db.redis import redis_conn
from flask import request
from flask_restx import Namespace, Resource, fields  # type: ignore
from models.users import Users
from werkzeug.exceptions import BadRequest, Forbidden, NotFound, Unauthorized

authorizations = schemas.authorizations
api = Namespace("users", description="Endpoint for work with users", authorizations=authorizations,
                url_prefix="/users")

api.logger.addHandler(file_handler)

model_response_400_401_403_404_base = api.model("ErrorBase", schemas.model_response_400_401_403_404_base)
model_user_login = api.model("UserLogin", schemas.model_user_login)
model_response_users_profile = api.model("ProfileResponse", schemas.model_response_users_profile)
model_user = api.model("User_email", schemas.model_user)
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
model_payment_log = api.model("model_payment_log", schemas.model_payment_log)
model_payment_log_list = {
    "logs": fields.List(fields.Nested(model_payment_log))
}


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
    # @api.doc(security=("captcha_token"))
    @api.expect(model_user_login)
    def post(self):
        """
        Login to the service
        """
        current_user = request.json
        headers_user = request.headers
        user_email = current_user["user_email"]
        password = current_user['password']
        try:
            user = Users.query.filter_by(email=user_email).first()
            if user is None:
                api.logger.info(f"User {user_email} not found")
                raise BadRequest(f"User {user_email} not found")
        except Exception:
            api.logger.info(f"User {user_email} not found")
            raise BadRequest(f"User {user_email} not found")
        user_log_agent = headers_user["User-Agent"]
        hash_password = hash.get_hash(password, user.created_at)
        if user.is_active is False:
            api.logger.info(f"user {user_email} not active")
            raise Unauthorized(f"user {user_email} not active")
        if user.password == hash_password:
            utils.write_log(user.id, user_log_agent, "success user login")
            api.logger.info(f"User {user_email} successful login")
            return utils.create_load_tokens(user_email, user.id, user.role_id)

        utils.write_log(user.id, user_log_agent, "unsuccess user login")
        api.logger.info("Username password broken")
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
            api.logger.info("Need refresh token")
            raise BadRequest("Need refresh token")
        refresh_payload = utils.get_payload(has_refresh_token)
        res["user_email"] = refresh_payload["user_email"]
        if refresh_payload["type"] == "refresh_token" and refresh_payload["Check_token"] is True:
            refresh_key = refresh_payload["user_id"] + "_refresh_token"
            refresh_key_value = refresh_payload["exp"]
            redis_conn.set(refresh_key, refresh_key_value, settings.TTL_REFRESH_TOKEN)
        else:
            api.logger.info("Refresh token broken")
            raise Unauthorized("Refresh token broken")
        res["status"] = "logout"
        try:
            utils.write_log(refresh_payload["user_id"], request.headers.get("User-Agent"), "success user logout")
            api.logger.info(f"User {refresh_payload['user_email']} logout")
        except Exception:
            logging.info(f"ERROR write log {refresh_payload['user_id']}, {request.headers.get('User-Agent')}")

        return res


@api.route("/profile")
class Profile(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_USERS, override_defaults=False)]

    @api.doc(
        description="Path access token in header 'access_token' to get path to user directory"
    )
    @api.response(200, 'Success', model_response_users_profile)
    @api.response(401, 'Unauthorized', model_response_400_401_403_404_base)
    @api.doc(security="access_token")
    @decor_function.active_required()
    def get(self):
        """
        Get path to the user directory
        """
        profile = {}
        try:
            payload = utils.get_payload(request.headers.get("access_token"))

            profile["user_email"] = payload["user_email"]
            if payload["type"] == "access_token":
                profile["redirect"] = f"/users/{payload['user_id']}/profile/"
            else:
                profile["Token status"] = payload["Check_token"]
                profile["Token type"] = payload["type"]
        except Exception:
            api.logger.info("Token broken")
            raise Unauthorized("token broken")
        api.logger.info(f"User {profile['user_email']} get redirect link")
        return profile


@api.route("/new-user")
class UserCheck(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_USERS, override_defaults=False)]

    @api.doc(
        responses={200: "OK"},
        description="New user will be created with defoult role='unsubcriber'"
    )
    @api.response(400, 'Bad Request', model_response_400_401_403_404_base)
    @api.doc(security="captcha_token")
    @api.expect(model_user)
    def post(self):
        """
        Create new user
        """
        captcha_token = request.headers.get("captcha_token")
        if captcha_token is None:
            api.logger.info("Captcha token not present")
            raise BadRequest("Captcha token not present")
        captcha_token_payload = utils.get_payload(captcha_token)
        if captcha_token_payload["Check_token"] is True and \
                captcha_token_payload["type"] == "captcha":
            user_params = request.json
            user = Users.query.filter_by(email=user_params["email"]).first()
            if user is not None:
                api.logger.info(f"User_name {user_params['email']} is busy")
                raise BadRequest(f"User_name {user_params['email']} is busy")
            res = utils.create_user(user_params)
            api.logger.info(res)
            return res
        api.logger.info("Captcha token broken")
        raise BadRequest("Captcha token broken")


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
    @decor_function.active_required()
    def get(self, user_id):
        """
        User profile
        """
        profile = {}
        try:
            if decor_function.check_self_user(request.headers.get("access_token"), user_id):
                profile = utils.make_user_profile(user_id, profile)
                api.logger.info(f"User {user_id} get profile")
                return profile
            api.logger.info("Token broken or have not permitins or not self")
            raise Forbidden("Token broken or have not permitins or not self")
        except Exception:
            api.logger.info("Token broken")
            raise Unauthorized("Token broken")

    @api.doc(
        params={'user_id': 'UUID'},
        description="Path access token via header 'access_token' to edit user profile."
    )
    @api.response(200, 'Success', model_response_users_id_profile_response_post)
    @api.response(404, 'Not found', model_response_400_401_403_404_base)
    @api.doc(security="access_token")
    @api.expect(model_profile)
    def patch(self, user_id):
        """
        Edit user profile
        """
        try:
            payload = utils.get_payload(request.headers.get("access_token"))
            if payload == "Token broken":
                api.logger.info("Token broken")
                raise Unauthorized("Token broken")
            request_dict = request.json

            logging.info(f"request_dict {request_dict}")
            profile = utils.update_profile(request_dict, payload, user_id)
            api.logger.info(f"User: {payload['user_id']} update profile {profile}")
            utils.write_log(payload["user_id"], request.headers.get('User-Agent'), "update user profile")

        except Exception:
            api.logger.info("is not exists")
            raise NotFound("is not exists")
        api.logger.info(f"User {user_id} profile updated")
        return profile


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
            api.logger.info("Page is not int or not exists")
            raise BadRequest("Page is not int or not exists")
        try:
            if decor_function.check_admin_or_self_user(request.headers["access_token"], user_id):
                api.logger.info(f"User {user_id} get logs")
                return utils.get_login_log_list(user_id, params)
            api.logger.info("Token is not self or admin")
            raise Forbidden("Token is not self or admin")
        except Exception:
            api.logger.info("Token broken")
            raise Unauthorized("Token broken")


@api.route("/confirm-email/<confirm_id>")
class Confirm(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_USERS, override_defaults=False)]

    @api.doc(
        params={'confirm_id': 'str'},
    )
    # @api.response(200, 'Success', model_response_users_id_profile_response_get)
    @api.response(401, 'Unauthorized', model_response_400_401_403_404_base)
    @api.response(403, 'Forbidden', model_response_400_401_403_404_base)
    # @api.doc(security="access_token")
    # @decor_function.active_required()
    def get(self, confirm_id):
        """
        Confirm email
        """

        try:
            response = user_settings.confirm_email(confirm_id)
            if response == "Confirm record not exists":
                api.logger.info("Confirm record not exists")
                raise Unauthorized("Confirm record not exists")
            if response == "Confirm time out":
                api.logger.info("Confirm time out")
                raise BadRequest("Confirm time out")
            api.logger.info(response)
            return response
        except Exception:
            api.logger.info("service broken")
            raise Unauthorized("service broken")


@api.route("/payments-user-logs/")
class PaymentsLogs(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_USERS, override_defaults=False)]

    @api.doc(
        description="Path access token via header 'access_token' to recive list of payments logs"
    )
    # @api.response(200, 'Success', model_payment_log_list)
    @api.response(401, 'Unauthorized', model_response_400_401_403_404_base)
    @api.response(403, 'Forbidden', model_response_400_401_403_404_base)
    @api.doc(security="access_token")
    def get(self):
        """
        List of user payment logs
        """
        payload = sjwt.checktoken.get_payload(key=settings.JWT_KEY, token=request.headers.get("access_token"))
        if "user_id" not in payload or payload["user_id"] is None or payload["Check_token"] is not True:
            api.logger.info("Token broken")
            raise Unauthorized("Token broken")
        payment_log_list = user.get_payment_logs(payload["user_id"])
        api.logger.info(f"User {payload['user_id']} get payment logs")
        print("payment_log_list", (payment_log_list))

        return payment_log_list
