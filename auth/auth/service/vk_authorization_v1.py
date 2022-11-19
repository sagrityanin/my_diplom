from flask import request
from flask_restx import Resource, Namespace  # type: ignore
from werkzeug.exceptions import BadRequest, Unauthorized

from core.rate_limiter import limiter  # type: ignore
from core import utils, schemas  # type: ignore
from core.ext_users import VkUser  # type: ignore
from core.config import settings  # type: ignore
from core.logger import file_handler  # type: ignore
from db.redis import redis_conn
from models.users import Users

authorizations = schemas.authorizations
api = Namespace("vk-com", description="External authorization by vk.com", authorizations=authorizations,
                url_prefix="ext_auth")

api.logger.addHandler(file_handler)

model_vk_user = api.model("VK user", schemas.model_vk_user)
model_token_payload_response = api.model("TokenPayload", schemas.model_token_payload_response)
model_response_400_401_403_404_base = api.model("ErrorBase", schemas.model_response_400_401_403_404_base)
model_response_400 = api.model("Need email", schemas.model_response_400_need_email)
model_set_email_vk_user = api.model("Set email for vk user", schemas.model_set_email_user)
common_token_field_list = ['user_email', "role", "user_id"]


@api.route("/vk-auth")
class VkBeginning(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_VK, override_defaults=False)]

    @api.doc(description="Redirect to vk.com for authorization ")
    @api.response(200, 'Success')
    @api.response(401, 'Unauthorized', model_response_400_401_403_404_base)
    @api.response(403, 'Forbidden', model_response_400_401_403_404_base)
    # @api.expect()
    def get(self):
        """
        Redirect to vk for getting access token
        """
        url = f"https://oauth.vk.com/authorize?client_id={settings.APP_VK_ID}&display=page&redirect_uri=https://oauth.vk.com/blank.html&scope=friends,email&response_type=token&v=5.131"
        api.logger.info("Redirect to externel autotenification")
        return {"redirect for autotenification": url}


@api.route("/vk-create-user")
class VkAuthorization(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_VK, override_defaults=False)]

    @api.doc(description="Redirect to vk.com for authorization ")
    @api.expect(model_vk_user)
    @api.response(200, 'Success')
    @api.response(400, 'Bad Request', model_response_400_401_403_404_base)
    @api.response(401, 'Unauthorized', model_response_400_401_403_404_base)
    @api.response(403, 'Forbidden', model_response_400_401_403_404_base)
    def post(self):
        """
        Create user by vk authentication
        """
        try:
            ext_user = VkUser(request.json["url"])
        except Exception:
            api.logger.info("Url broken")
            raise BadRequest("Url broken")
        if ext_user.check_vk_user() or ext_user.test_case == settings.TEST_CASE:

            check_email = ext_user.check_email()
            if check_email is not None:
                api.logger.info(check_email)
                return check_email
            if ext_user.check_exists_user():
                api.logger.info(f"User_name {ext_user.email} is busy")
                raise BadRequest(f"User_name {ext_user.email} is busy")
            ext_user.password = "ext_vk_login"
            res = ext_user.create_ext_login_user()
            redis_conn.set(ext_user.email, ext_user.access_token, ext_user.expires_in)
            api.logger.info(res)
            return res
        api.logger.info("VK access token broken")
        raise BadRequest("VK access token broken")


@api.route("/vk-login")
class VkLogin(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_VK, override_defaults=False)]

    @api.doc(description="Redirect to vk.com for authorization ")
    @api.expect(model_vk_user)
    @api.response(200, 'Success')
    @api.response(401, 'Unauthorized', model_response_400_401_403_404_base)
    @api.response(403, 'Forbidden', model_response_400_401_403_404_base)
    def post(self):
        """
           Login user by vk authentication
        """
        try:
            ext_user = VkUser(request.json["url"])
        except Exception:
            api.logger.info("Url broken")
            raise BadRequest("Url broken")
        if ext_user.check_vk_user() or ext_user.test_case == settings.TEST_CASE:
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
            api.logger.info(f"{user.id} success user login")
            return utils.create_load_tokens(ext_user.email, user.id, user.role_id)
        utils.write_log(ext_user.email, "vk access token", "unsuccess user login")
        api.logger.info("vk access token broken")
        raise Unauthorized("vk access token broken")


@api.route("/vk-set-email")
class VkAuthorizationSetEmail(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_VK, override_defaults=False)]

    @api.doc(description="Set email for create user ")
    @api.expect(model_set_email_vk_user)
    @api.response(200, 'Success')
    @api.response(400, 'Bad Request', model_response_400_401_403_404_base)
    @api.response(401, 'Unauthorized', model_response_400_401_403_404_base)
    @api.response(403, 'Forbidden', model_response_400_401_403_404_base)
    @api.doc(security='vk_access_token')
    def post(self):
        """
            Set email for user with vk authentication if not present email
        """
        current_user = request.json
        headers = request.headers
        url = f"https://{current_user['ext_auth_source']}#access_token={headers['vk_access_token']}&expires_in={current_user['user_ext_id']}&user_id={current_user['user_ext_id']}&email={current_user['email']}&test_case={current_user['test_case']}"
        ext_user = VkUser(url)
        try:
            if ext_user.check_vk_user() or ext_user.test_case == settings.TEST_CASE:
                user = Users.query.filter_by(email=ext_user.email).first()
                if user is not None:
                    api.logger.info(f"User_name {ext_user.email} is busy")
                    raise BadRequest(f"User_name {ext_user.email} is busy")
                ext_user.password = "ext_vk_login"
                res = ext_user.create_ext_login_user()
                redis_conn.set(ext_user.email, ext_user.access_token, ext_user.expires_in)
                api.logger.info(res)
                return res
            api.logger.info("vk access token broken")
            raise Unauthorized("vk access token broken")
        except Exception:
            api.logger.info("Invalid request body or headers")
            raise BadRequest("Invalid request body or headers")
