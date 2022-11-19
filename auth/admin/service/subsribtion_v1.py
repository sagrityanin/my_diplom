from flask_restx import Resource, Namespace  # type: ignore
from flask import request

from core.config import settings  # type: ignore
from core import schemas, decor_function  # type: ignore
from core.rate_limiter import limiter  # type: ignore
from core import subscribtion

from core.logger import file_handler  # type: ignore

authorizations = schemas.authorizations
api = Namespace("promo-subscribtion", description="API for work with promo", authorizations=authorizations,
                url_prefix="/")
api.logger.addHandler(file_handler)

model_promo = api.model("Promo subscribtion", schemas.model_promo)
model_response_400_401_403_404_base = api.model("ErrorBase", schemas.model_response_400_401_403_404_base)

model_promo = api.model("User_email", schemas.model_promo)
model_response_400_401_403_404_base = api.model("ErrorBase", schemas.model_response_400_401_403_404_base)


@api.route("/set-promo")
class Subscribtion(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_USERS, override_defaults=False)]

    @api.doc(
        responses={200: "OK"},
        description="Manage promo subscribtion"
    )
    @api.doc(security=("access_token"))
    @decor_function.active_required()
    @decor_function.admin_required()
    @api.response(400, 'Bad Request', model_response_400_401_403_404_base)
    @api.expect(model_promo)
    def put(self):
        """
        Create promo subscribtion
        """
        requesty_params = request.json
        api.logger.info(requesty_params)

        res = subscribtion.make_promo(requesty_params["users"], requesty_params["price_id"])
        api.logger.info(res)
        return res
