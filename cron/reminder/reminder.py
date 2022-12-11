import datetime
import logging
import sys
import time
import uuid

import psycopg2
import repackage
from psycopg2.extras import DictCursor
from rabbitmq import queue

repackage.up()
import backoff
from config import settings

# STEP = 1000
REMINDER_INTERVAL = 2

log = logging.getLogger('')
log.setLevel(logging.INFO)
format = logging.Formatter("%(asctime)s - reminder - %(levelname)s - %(message)s")

ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(format)
log.addHandler(ch)


@backoff.backoff()
def make_message(email: str, exp_date) -> None:
    email_id = str(uuid.uuid4())
    message = f"Dear customer. Your subscribtion is ending {exp_date}"
    subject = "Your subscribtion is ending"
    res = queue.make_message(email_id, email, message, subject)
    logging.info(res)


@backoff.backoff()
def check_continuation_subscribtion(user_id: str, cursor: psycopg2.extras.DictCursor) -> bool:
    query = f"select subscribtion_expiration_datetime from subscribtion where user_id = '{user_id}' \
        order by subscribtion_expiration_datetime DESC LIMIT 1;"
    cursor.execute(query)
    res = cursor.fetchone()[0]
    check_boder = datetime.datetime.now() + datetime.timedelta(days=REMINDER_INTERVAL)
    if res > check_boder:
        return True
    return False


@backoff.backoff()
def make_reminder_list() -> None:
    with psycopg2.connect(
            host=settings.AUTH_POSTGRES_HOST, port=settings.AUTH_POSTGRES_PORT,
            user=settings.AUTH_POSTGRES_USER,
            password=settings.AUTH_POSTGRES_PASSWORD, database=settings.AUTH_POSTGRES_DB
    ) as postgres_conn:
        cursor = postgres_conn.cursor(cursor_factory=DictCursor)
        query = f"SELECT * FROM subscribtion WHERE payment_status = 'payment_completed' and \
               subscribtion_expiration_datetime > now() and \
                subscribtion_expiration_datetime < now() + '{REMINDER_INTERVAL} day'\
                and auto_renewal = false;"
        cursor.execute(query)
        while reminder_user_list := cursor.fetchmany(settings.REMINDER_STEP):
            for subscribtion in reminder_user_list:
                if check_continuation_subscribtion(subscribtion['user_id'], cursor):
                    continue
                user_query = f"SELECT email FROM users WHERE id = '{subscribtion['user_id']}';"
                logging.info(f"Make reminder message for {subscribtion['user_id']}")
                cursor.execute(user_query)
                email = cursor.fetchone()[0]
                make_message(email, subscribtion["subscribtion_expiration_datetime"])


if __name__ == "__main__":
    while True:
        make_reminder_list()
        time.sleep(settings.PAUSE)
