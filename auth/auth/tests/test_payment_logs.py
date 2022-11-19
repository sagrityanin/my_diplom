# flake8: noqa
import requests  # type: ignore
import psycopg2  # type: ignore
from psycopg2.extras import DictCursor
import random
import json
import uuid
from bs4 import BeautifulSoup
from datetime import datetime

import pytest
# import token_test
import sjwt

import repackage # type: ignore

repackage.up()
from core.config import settings # type: ignore

params = {}




@pytest.fixture()
def get_conn():
    conn = psycopg2.connect(host=settings.AUTH_POSTGRES_HOST, user=settings.AUTH_POSTGRES_USER,
                            password=settings.AUTH_POSTGRES_PASSWORD,
                            database=settings.AUTH_POSTGRES_DB)
    yield conn
    conn.close()


@pytest.fixture()
def get_cursor(get_conn):
    cursor = get_conn.cursor(cursor_factory=DictCursor)
    return cursor

def get_user_id() -> str:
    payload = {"user_id": "user_id", "role": "admin", "type": "access_token"}
    current_token = sjwt.gettoken.get_token(settings.JWT_KEY, **payload)
    headers = {"access_token": current_token}
    url = "http://admin:5000/admin/api/v1/user/users-list?sort_order=asc&sort_field=email&page_number=1&page_size=5"
    res = requests.get(url, headers=headers).json()
    params["user_id"] = list(filter(lambda x: x["email"] == "sagrityanin@yandex.ru", res["users"]))[0]["id"]
    return params["user_id"]

def test_get_subscriptions():
    user_id = get_user_id()
    url = "http://payments-client:8080/api/v1/subcriptions/"
    payload = {"user_id": user_id, "role": "admin", "type": "access_token",
               "user_email": "sagrityanin@yandex.ru"}
    current_token = sjwt.gettoken.get_token(settings.JWT_KEY, **payload)
    params["headers"] = {"Authorization": f"Bearer {current_token}"}
    # new_headers = {"Authorization": f"Bearer {current_token}"}
    res = requests.get(url, headers=params["headers"]).json()
    params["price_id_1"] = list(filter(lambda x: x["duration"] == 1, res))[0]["id"]
    assert len(res) > 0
    duration = [x["duration"] for x in res]
    assert 1 in duration
    assert 7 in duration
    assert 14 in duration
    assert 30 in duration

def test_get_description_price():
    url = f"http://payments-client:8080/api/v1/subcriptions/{params['price_id_1']}/"
    res = requests.get(url, headers=params["headers"]).json()
    assert res["duration"] == 1

def test_payments_log(get_conn, get_cursor):

    subscription_query = "select id, user_id from subscribtion"
    get_cursor.execute(subscription_query)
    subscriptions = get_cursor.fetchall()
    url = "http://127.0.0.1:5000/auth/api/v1/users/payments-user-logs/"
    for subscribtion in subscriptions:
        provider = random.choice(["provider1", "provider2"])
        status = random.choice(["completed", "waiting"])
        raw = {"id": "id1223", "invoice": "my_invoice"}
        query = f"INSERT INTO payments_log (id, event_time, subscription_id, provider, status, raw) VALUES " \
                f"('{uuid.uuid4()}', '{datetime.now()}',  '{subscribtion[0]}', '{provider}', " \
                f"'{status}', '{json.dumps(raw)}');"
        get_cursor.execute(query)
        get_conn.commit()
        payload = {"user_id": subscribtion[1], "role": "unsubscriber", "type": "access_token"}
        current_token = sjwt.gettoken.get_token(settings.JWT_KEY, **payload)
        headers = {"access_token": current_token}
        response = requests.get(url, headers=headers).json()
        assert response[0]["subscription_id"] is not None

def test_get_my_subscription():
    url = "http://payments-client:8080/api/v1/subcriptions/my/subscription/"
    res = requests.get(url, headers=params["headers"]).json()
    params["order_id"] = res["subscription"]["id"]
    assert res["subscription"]["user_id"] == params["user_id"]
    assert res["price"]["duration"] == 1

def test_get_link_for_pay_order(get_conn, get_cursor):
    url = "http://payments-client:8080/api/v1/subcriptions/my/subscription/"
    body = {
      "subscription_id": params["price_id_1"],
      "start_date": str(datetime.now()),
      "referer": "string"
    }
    res = requests.post(url, headers=params["headers"], json=body).json()
    assert res["type"] == "redirect"
    assert res["response_from_pay"] == "success"
    get_cursor.execute("TRUNCATE subscribtion;")
    get_conn.commit()


def test_make_callback_for_pay_widget_response():
    url = "http://payments-api:8000/api/v1/paid/"
    body = {
          "user_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "subscription_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "provider": "providers.cloudpayments.CloudPayments",
          "success": True,
          "message": "string",
          "code": 0
    }
    res = requests.post(url, json=body)
    assert res.status_code == 200

def test_get_pay_widget():
    base64json = "eyJ0ZW1wbGF0ZSI6ICJjbG91ZHBheW1lbnRzLmh0bWwiLCAib25fY29tcGxldGVkX2NhbGxiYWNrIjogImh0dHBzOi8vcHljaW5lbWEucnUvcGF5bWVudHMvYXBpL3YxL3BhaWQvIiwgImRlc2NyaXB0aW9uIjogIlx1MDQxZVx1MDQzZlx1MDQzYlx1MDQzMFx1MDQ0Mlx1MDQzMCBcdTA0M2ZcdTA0M2VcdTA0MzRcdTA0M2ZcdTA0MzhcdTA0NDFcdTA0M2FcdTA0MzggXHUwNDMyIHB5Y2luZW1hLnJ1IiwgInByaWNlIjogMjAuMCwgImN1cnJlbmN5IjogInJ1YiIsICJ1c2VyX2lkIjogImYxMGZmYWM4LTBhNGQtNDMwNS1hYjI5LTg1NTA1ZGFlMDM4MCIsICJzdWJzY3JpcHRpb25faWQiOiAiYzY3OGY2OTEtYzE4Yi00ZWVlLTk0NjktMWIwMWE2MTkwY2M3IiwgImVtYWlsIjogInRlc3RAY28uY29tIiwgImxhbmd1YWdlIjogInJ1LVJVIiwgImRhdGEiOiB7InJlZmVyZXIiOiAic3RyaW5nIn19"
    url = f"http://payments-api:8000/api/v1/pay/{base64json}"
    res = requests.get(url, headers={"accept": "text/html"})
    html = res.content.decode("utf-8")
    soup = BeautifulSoup(html, features="html.parser")
    assert soup.title.string == "Оплата подписки"

