import flask
import sjwt  # type: ignore

from flask import request
from flask_restx import Namespace, Resource  # type: ignore
from werkzeug.exceptions import BadRequest, Unauthorized

from core import schemas  # type: ignore
from core.config import settings  # type: ignore
from core.logger import file_handler  # type: ignore
from core.rate_limiter import limiter  # type: ignore
from service.user_token import TokenClass
from service.user import UserClass
from service.user_settings import UserSettings

authorizations = schemas.authorizations
api = Namespace("token", description="Endpoint for workwith token", authorizations=authorizations, url_prefix="/token")

api.logger.addHandler(file_handler)
model_payload = api.model("Payload", schemas.model_payload)
model_token_payload_response = api.model("TokenPayload", schemas.model_token_payload_response)
model_response_400_401_403_404_base = api.model("ErrorBase", schemas.model_response_400_401_403_404_base)

common_token_field_list = ['user_email', "role", "user_id"]


@api.route("/token-get")
class TokenGet(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_TOKEN, override_defaults=False)]

    @api.doc(
        responses={200: 'Success'},
        description="Get access token from header 'access_token' in response",
        headers={"access_token": "JWT"})
    @api.expect(model_payload)
    def post(self):
        """
        Endpoint for test
        """
        payload = request.json
        new_token = sjwt.gettoken.get_token(settings.JWT_KEY, **payload)
        resp = flask.Response("Token generated")
        resp.headers["access_token"] = new_token
        return resp


@api.route("/token-get-payload")
class PayloadGet(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_TOKEN, override_defaults=False)]

    @api.doc(
        description="Decode token, endpoint for other services. Path access token in header ''access_token'"
    )
    @api.response(200, 'Success')
    @api.response(401, 'Unauthorized', model_response_400_401_403_404_base)
    @api.response(403, 'Forbidden', model_response_400_401_403_404_base)
    @api.doc(security='access_token')
    @TokenClass.token_required
    @api.expect()
    def get(self):
        """
        Parse token
        """
        api.logger.info("Get payload")
        return sjwt.checktoken.get_payload(key=settings.JWT_KEY, token=request.headers["access_token"])


@api.route("/token-reissue")
class TokenReissue(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_TOKEN, override_defaults=False)]

    @api.doc(
        description="Path your refresh token in header 'refresh_token', to recive new acces and refresh tokens",
    )
    @api.response(200, 'Success', headers={"access_token": "JWT", "refresh_token": "JWT"})
    @api.response(400, 'Bad Request', model_response_400_401_403_404_base)
    @api.response(403, 'Forbidden', model_response_400_401_403_404_base)
    @api.doc(security="refresh_token")
    def get(self):
        """
        Refresh your tokens
        """
        try:
            payload = sjwt.checktoken.get_payload(key=settings.JWT_KEY, token=request.headers["refresh_token"])
        except Exception:
            api.logger.info("Have not refresh_token")
            raise BadRequest("Have not refresh_token")
        if payload['Check_token'] is not True:
            api.logger.info("Not allow")
            raise Unauthorized("Not allow")
        if payload["type"] != "refresh_token":
            api.logger.info("Broken token type")
            raise BadRequest("Broken token type")
        if TokenClass.get_token_from_redis(payload):
            api.logger.info(f"User {payload['user_id']} has logout")
            raise Unauthorized(f"User {payload['user_id']} has logout")
        resp = flask.Response("Token generated")
        new_payload = {}
        if UserSettings.check_user_subscription(payload["user_id"]):
            payload["role"] = "subscriber"
        else:
            payload["role"] = "unsubscriber"
        for field in common_token_field_list:
            new_payload[field] = payload[field]
        list_token = TokenClass.create_two_token(new_payload)
        for token in list_token:
            resp.headers[token] = list_token[token]
        UserClass.write_log(new_payload["user_id"], "TokenReissue", "success token recreate")
        api.logger.info(f"{new_payload['user_id']} TokenReissue success token recreate")
        return resp
