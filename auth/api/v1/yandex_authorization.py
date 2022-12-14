from core import schemas, utils  # type: ignore
from core.config import settings  # type: ignore
from service.ext_users import YandexUser  # type: ignore
from core.logger import file_handler  # type: ignore
from core.rate_limiter import limiter  # type: ignore
from db.redis import redis_conn
from flask import request
from flask_restx import Namespace, Resource  # type: ignore
from models.ext_auth import ExtAuth
from models.users import Users
from werkzeug.exceptions import BadRequest, Unauthorized

authorizations = schemas.authorizations
api = Namespace("yandex", description="External authorization by yandex", authorizations=authorizations,
                url_prefix="ext_auth")

api.logger.addHandler(file_handler)

model_yandex_user = api.model("Yandex user", schemas.model_vk_user)
model_token_payload_response = api.model("TokenPayload", schemas.model_token_payload_response)
model_response_400_401_403_404_base = api.model("ErrorBase", schemas.model_response_400_401_403_404_base)
model_set_email_yandex_user = api.model("Set email for ext user", schemas.model_set_email_user)
common_token_field_list = ['user_email', "role", "user_id"]


@api.route("/yandex-auth")
class YandexBeginning(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_YA, override_defaults=False)]

    @api.doc(description="Redirect to yandex for authorization ")
    @api.response(200, 'Success')
    @api.response(401, 'Unauthorized', model_response_400_401_403_404_base)
    @api.response(403, 'Forbidden', model_response_400_401_403_404_base)
    def get(self):
        """
        Redirect to yandex for  getting access token
        """
        url = f"https://oauth.yandex.ru/authorize?response_type=token&client_id={settings.APP_YANDEX_ID}"
        api.logger.info("redirect for autotenification")
        return {"redirect for autotenification": url}


@api.route("/yandex-create-user")
class YandexGetToken(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_YA, override_defaults=False)]

    @api.doc(description="Redirect to yandex for authorization ")
    @api.expect(model_yandex_user)
    @api.response(200, 'Success')
    @api.response(400, 'Bad Request', model_response_400_401_403_404_base)
    @api.response(401, 'Unauthorized', model_response_400_401_403_404_base)
    @api.response(403, 'Forbidden', model_response_400_401_403_404_base)
    def post(self):
        """
        Create user by yandex authentication
        """
        ext_user = YandexUser(request.json["url"])
        ext_user.ext_auth_source = "login.yandex.ru"
        try:
            get_yandex_user_data = ext_user.get_yandex_user_data()
            if get_yandex_user_data == "Bad token":
                api.logger.info("Bad request")
                raise BadRequest("Bad request")
            check_email = ext_user.check_email()
            if check_email is not None:
                api.logger.info(check_email)
                return check_email
            if ext_user.check_exists_user():
                api.logger.info(f"User_name {ext_user.email} is busy")
                return {"status": f"User_name {ext_user.email} is busy"}

            ext_user.password = "ext_yandex_login"
            ext_user.create_ext_login_user()
            redis_conn.set(ext_user.email, ext_user.access_token, ext_user.expires_in)
            api.logger.info(f"User {ext_user.email} created")
            return {"status": f"User {ext_user.email} created"}
        except Exception:
            return {"yandex access token": "broken"}


@api.route("/yandex-login")
class YaLogin(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_YA, override_defaults=False)]

    @api.doc(description="Redirect to yandex for authorization ")
    @api.expect(model_yandex_user)
    @api.response(200, 'Success')
    @api.response(401, 'Unauthorized', model_response_400_401_403_404_base)
    @api.response(403, 'Forbidden', model_response_400_401_403_404_base)
    def post(self):
        """
        login user with yandex authentication
        """
        ext_user = YandexUser(request.json["url"])
        ext_user.ext_auth_source = "login.yandex.ru"
        try:
            get_yandex_user_data = ext_user.get_yandex_user_data()
            if get_yandex_user_data == "Bad token":
                api.logger.info("Bad request")
                raise BadRequest("Bad request")
        except Exception:
            api.logger.info("Token broken")
            return {"token": "broken"}
        user = Users.query.filter_by(user_ext_id=ext_user.user_ext_id).first()
        if user is None:
            api.logger.info(f"User_name {ext_user.email} not found")
            raise BadRequest(f"User_name {ext_user.email} not found")
        headers_user = request.headers
        user_log_agent = headers_user["User-Agent"]
        if user.is_active is False:
            api.logger.info(f"user {ext_user.email} not active")
            raise Unauthorized(f"user {ext_user.email} not active")
        utils.write_log(user.id, user_log_agent, "success user login")
        api.logger.info(f"User {ext_user.email} successful login")
        return utils.create_load_tokens(ext_user.email, user.id, user.role_id)


@api.route("/yandex-set-email")
class YandexAuthorizationSetEmail(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_YA, override_defaults=False)]

    @api.doc(description="Set email for create user ")
    @api.expect(model_set_email_yandex_user)
    @api.response(200, 'Success')
    @api.response(401, 'Unauthorized', model_response_400_401_403_404_base)
    @api.response(403, 'Forbidden', model_response_400_401_403_404_base)
    @api.doc(security='ya_access_token')
    def post(self):
        """
            Set email for user with yandex authentication if not present email
        """

        current_user = request.json
        headers = request.headers
        url = f"https://{current_user['ext_auth_source']}#access_token={headers['ext_access_token']}&expires_in={current_user['user_ext_id']}&user_id={current_user['user_ext_id']}&email={current_user['email']}&test_case={current_user['test_case']}"
        ext_user = YandexUser(url)
        ext_user.password = "ext_yandex_login"
        ext_auth_source = ExtAuth.query.filter_by(auth_source=ext_user.ext_auth_source).first()
        user = Users.query.filter_by(user_ext_id=ext_user.user_ext_id,
                                     ext_auth_source_id=ext_auth_source.id).first()
        if user is not None:
            api.logger.info(f"User_name {ext_user.email} is busy")
            raise BadRequest(f"User_name {ext_user.email} is busy")
        try:
            ext_user.create_ext_login_user()
            redis_conn.set(ext_user.email, ext_user.access_token, int(current_user["expires_in"]))
        except Exception:
            api.logger.info("Data is broken ")
            raise BadRequest("Data is broken ")
        api.logger.info(f"User  {current_user['email']} created")
        return {"status": f"User  {current_user['email']} created"}
