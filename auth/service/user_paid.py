import logging
from datetime import datetime
from typing import Optional

from models.payments_log import PaymentsLog
from models.subscribtion import Subscribtion


class User:
    def make_log_dict(self, log_row):
        result = {
            "id": str(log_row.id),
            "subscription_id": str(log_row.subscription_id),
            "event_time": str(log_row.event_time),
            "provider": log_row.provider,
            "status": log_row.status,
            "row": log_row.raw
        }
        return result

    def get_payment_logs(self, user_id: str) -> Optional[list]:
        now = datetime.now()
        subscription = Subscribtion.query.filter(Subscribtion.user_id == user_id,
                                                 Subscribtion.subscribtion_expiration_datetime > now,
                                                 Subscribtion.start_subscribtion < now).order_by(
            Subscribtion.subscribtion_expiration_datetime.desc()).first()
        logging.info(f"subscription {subscription}")
        if subscription is None:
            return []
        payment_logs = PaymentsLog.query.filter(PaymentsLog.subscription_id == subscription.id). \
            order_by(PaymentsLog.event_time.desc()).all()

        response = [self.make_log_dict(payment_log) for payment_log in payment_logs]
        return response


user = User()
