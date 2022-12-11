import logging
import sjwt
from flask import request
from flask_api import status
from flask_restx import Namespace, Resource  # type: ignore

from core import schemas  # type: ignore
from service import decor_function  # type: ignore
from service.price import price
from core.config import settings  # type: ignore
from core.logger import file_handler  # type: ignore
from service.rate_limiter import limiter  # type: ignore

authorizations = schemas.authorizations
api = Namespace("price", description="API for work with price", authorizations=authorizations,
                url_prefix="/")
api.logger.addHandler(file_handler)

model_subscibtion_create = api.model("Subscribtion", schemas.model_subscibtion_create)
model_response_400_401_403_404_base = api.model("ErrorBase", schemas.model_response_400_401_403_404_base)


@api.route("/arhive")
class PriceArhive(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_USERS, override_defaults=False)]

    @api.doc(
        responses={200: "OK"},
        description="Get arhive subscribtion price",
        security=("access_token")
    )
    @api.doc(security=("access_token"))
    @decor_function.active_required()
    @decor_function.admin_required()
    def get(self) -> list:
        """
        Get arhive subscription price
        """
        try:
            res = price.get_arhive_subscribtion()
            api.logger.info(res)
            return res
        except Exception as e:
            api.logger.info(e)
            return e, status.HTTP_400_BAD_REQUEST


@api.route("/")
class Price(Resource):
    decorators = [limiter.limit(settings.RATE_LIMIT_USERS, override_defaults=False)]

    @api.doc(
        responses={200: "OK"},
        description="Get active subscribtion price",
        security=("access_token")
    )
    @api.doc(security=("access_token"))
    @decor_function.active_required()
    @decor_function.admin_required()
    def get(self) -> list:
        """
        Get active subscription price
        """
        try:
            res = price.get_active_subscribtion()
            api.logger.info(res)
            return res
        except Exception as e:
            api.logger.info(e)
            return e, status.HTTP_400_BAD_REQUEST

    @api.doc(
        responses={200: "OK"},
        description="Manage subscribtion price"
    )
    @api.doc(security=("access_token"))
    @decor_function.active_required()
    @decor_function.admin_required()
    @api.expect(model_subscibtion_create)
    def put(self) -> str:
        """
        Create  subscription price
        """
        price_params = request.json
        logging.info(price_params)
        admin_id = sjwt.checktoken.get_payload(key=settings.JWT_KEY,
                                               token=request.headers.get("access_token"))["user_id"]
        try:
            res = price.set_price(price_params, admin_id)
            api.logger.info(f"admin_id: {admin_id} {res}")
            if "Broken currency" in res:
                return res, status.HTTP_400_BAD_REQUEST
            return res
        except Exception as e:
            api.logger.info(e)
            return e

    @api.doc(
        responses={200: "OK"},
        description="Delete subscribtion price"
    )
    @api.param("price_id", required=True)
    @api.doc(security=("access_token"))
    @decor_function.active_required()
    @decor_function.admin_required()
    def delete(self):
        """
        Disable subscription price
        """
        try:
            price_id = request.args.get("price_id")
        except Exception as e:
            api.logger.info(e)
            return "Price_id not present", status.HTTP_400_BAD_REQUEST
        admin_id = sjwt.checktoken.get_payload(key=settings.JWT_KEY,
                                               token=request.headers.get("access_token"))["user_id"]
        res = price.delete_price_record(price_id)
        api.logger.info(res + " by admin_id " + admin_id)
        if "not exists" in res or "is not uuid format" in res:
            return res, status.HTTP_400_BAD_REQUEST
        return res
