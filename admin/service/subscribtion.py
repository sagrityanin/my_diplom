import datetime
import logging
import uuid

from db.postgres import db
from models.price import Price
from models.subscribtion import Subscribtion
from models.users import Users

logging.basicConfig(filename='logs/admin.log', level=logging.info)



def check_price_id(price_id: str) -> bool:
    has_price = Price.query.filter_by(id=price_id, is_active=True).first()
    if has_price is not None:
        return True
    else:
        return False


def check_user_id(user_id):
    has_user = Users.query.filter_by(id=user_id).first()
    if has_user is not None:
        return True
    else:
        return False


def get_price_duration(price_id: str) -> int:
    price = Price.query.filter_by(id=price_id).first()
    return price.duration


def make_promo(users: list, price_id: str) -> str:
    response = {"price_id": price_id, "users_set_price": [], "users_not_set_price": []}
    try:
        if uuid.UUID(price_id):
            if not check_price_id(price_id):
                return f"Price_id {price_id} not in active price list"
    except Exception:
        return f"price_id {price_id} is not uuid format"
    duration = get_price_duration(price_id)
    start_time = datetime.datetime.now()
    finish_time = start_time + datetime.timedelta(days=duration)
    for user in users:
        try:
            if uuid.UUID(user):
                if check_user_id(user):
                    subscribtion = Subscribtion(user_id=uuid.UUID(user, version=4), invoce_created=start_time,
                                                payment_datetime=start_time, start_subscribtion=start_time,
                                                subscribtion_expiration_datetime=finish_time,
                                                price_id=uuid.UUID(price_id, version=4),
                                                payment_status="payment_completed"
                                                )
                    db.session.add(subscribtion)
                    db.session.commit()
                    response["users_set_price"].append(user)
                    logging.info(f"Price: user_id {user} set price {price_id}")
                else:
                    response["users_not_set_price"].append(user)
                    logging.info(f"user_id {user} is not set price")
        except Exception:
            response["users_not_set_price"].append(user)
            logging.info(f"user_id {user} is not uuid format")

    return response
