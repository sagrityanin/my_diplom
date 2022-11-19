import logging
import uuid

from db.postgres import db
from models.price import Price, Currency


def set_price(price_dict: dict, admin_id: str):
    if price_dict["currency"] not in [member.value for member in Currency]:
        return f"Broken currency {price_dict['currency']}"
    try:
        price_record = Price(duration=price_dict["duration"], price=price_dict["price"],
                             currency=price_dict["currency"], admin_id=admin_id,
                             is_active=True)
        db.session.add(price_record)
        db.session.commit()
        return f"Set price record {price_record.duration} days, price_id {price_record.id}"
    except Exception as e:
        return e


def get_active_subscribtion() -> list:
    list_subscribtions = Price.query.filter_by(is_active=True)
    result = []
    for subscribtion in list_subscribtions:
        result.append({
            "id": str(subscribtion.id), "duration": subscribtion.duration,
            "price": subscribtion.price, "currency": subscribtion.currency.value,
            "created": str(subscribtion.created_at), "admin_id": subscribtion.admin_id
        })
    return result


def get_arhive_subscribtion() -> list:
    list_subscribtions = Price.query.filter_by(is_active=False)
    result = []
    for subscribtion in list_subscribtions:
        result.append({
            "id": str(subscribtion.id), "duration": subscribtion.duration,
            "price": subscribtion.price, "currency": subscribtion.currency.value,
            "created": str(subscribtion.created_at), "admin_id": subscribtion.admin_id
        })
    return result


def delete_price_record(price_id: str) -> str:
    try:
        if uuid.UUID(price_id):
            pass
    except Exception:
        return f"price_id {price_id} is not uuid format"
    price_row = Price.query.filter_by(id=price_id).first()
    if price_row is None:
        logging.info(f"Price record with id = {price_id} not exists")
        return f"Price record with id = {price_id} not exists"
    price_row.is_active = False
    db.session.add(price_row)
    db.session.commit()
    logging.info(f"Price record with id = {price_id} disable")
    return f"Price record with id = {price_id} disable"
