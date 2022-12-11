from datetime import datetime
import logging
import psycopg2
import repackage
import requests
import time
import sys
from psycopg2.extras import DictCursor

repackage.up()
import backoff
from config import settings

# STEP = 1000
# inteval in mines
RENEWAL_INTERVAL = settings.RENEWAL_INTERVAL

log = logging.getLogger('')
log.setLevel(logging.INFO)
format = logging.Formatter("%(asctime)s - renewal - %(levelname)s - %(message)s")

ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(format)
log.addHandler(ch)
repay_url = "http://payments-api:8000/api/v1/repay"
PROVIDER = "providers.cloudpayments.CloudPayments"


@backoff.backoff()
def make_renewal_list() -> list:
    with psycopg2.connect(
            host=settings.AUTH_POSTGRES_HOST, port=settings.AUTH_POSTGRES_PORT,
            user=settings.AUTH_POSTGRES_USER,
            password=settings.AUTH_POSTGRES_PASSWORD, database=settings.AUTH_POSTGRES_DB
    ) as postgres_conn:
        cursor = postgres_conn.cursor(cursor_factory=DictCursor)
        query = f"SELECT id, user_id FROM subscribtion WHERE payment_status = 'payment_completed' and \
               subscribtion_expiration_datetime > now() and \
                subscribtion_expiration_datetime < now() + '{RENEWAL_INTERVAL} minutes' \
                and auto_renewal = true;"
        cursor.execute(query)
        logging.info(f"Start auto_renewall {datetime.now()}")
        while renewal_list := cursor.fetchmany(settings.RENEWAL_STEP):
            yield renewal_list


@backoff.backoff()
def renewal() -> None:
    s_list = make_renewal_list()
    for items in s_list:
        subscription_list = items
        for subscription in subscription_list:
            data = {"user_id": subscription[1], "subscription_id": subscription[0],
                    "provider": PROVIDER}
            res = requests.post(repay_url, json=data)
            logging.info(f"Make renewal for {subscription['user_id']} {res.content}")


if __name__ == "__main__":
    while True:
        renewal()
        time.sleep(settings.RENEWAL_INTERVAL*60)
