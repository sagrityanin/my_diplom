import flask
from flask import request
from flask_restx import Namespace, Resource  # type: ignore
from werkzeug.exceptions import BadRequest, Unauthorized

from core import schemas, token  # type: ignore
from service import utils  # type: ignore
from core.config import settings  # type: ignore
from core.logger import file_handler  # type: ignore
from service.rate_limiter import limiter  # type: ignore

from payload_get.token_payload import get_payload_sjwt  # type: ignore


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
        token_item = token.TokenGet(payload)
        new_token = token_item.get_token()
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
    @utils.token_required
    @api.expect()
    def get(self):
        """
        Parse token
        """
        return get_payload_sjwt(request.headers["access_token"])


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
            payload = get_payload_sjwt(request.headers["refresh_token"])
        except Exception:
            raise BadRequest("Have not refresh_token")
        if payload['Check_token'] is not True:
            raise Unauthorized('Not allow')
        if payload['type'] != 'refresh_token':
            raise BadRequest("Broken token type")
        if utils.get_token_from_redis(payload):
            raise Unauthorized(f"User {payload['user_id']} has logout")
        resp = flask.Response("Token generated")
        new_payload = {}
        for field in common_token_field_list:
            new_payload[field] = payload[field]
        list_token = utils.create_two_token(new_payload)
        for t_token in list_token:
            resp.headers[t_token] = list_token[t_token]
        utils.write_log(new_payload["user_id"], "TokenReissue", "success token recreate")
        return resp
