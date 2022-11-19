# flake8: noqa
import requests
import pytest
import psycopg2

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
    cursor = get_conn.cursor()
    return cursor


def test_yandex_user_create():
    url = "http://auth:5000/auth/api/v1/yandex/yandex-create-user"
    send_url = f"https://www.dynfor.ru/#access_token=qwertyu12345&token_type=bearer&expires_in=31536000&test_case={settings.TEST_CASE}"
    body_request = {"url": send_url}
    res = requests.post(url, json=body_request)
    assert res.json()["status"] == "User yandex_test@co.com created"


def test_yandex_user_create_without_email():
    url = "http://auth:5000/auth/api/v1/yandex/yandex-create-user"
    send_url = f"https://www.dynfor.ru/#access_token=qwertyu12345&token_type=bearer&expires_in=31536000&test_case={settings.TEST_CASE_WITHOUT_EMAIL}"
    body_request = {"url": send_url}
    res = requests.post(url, json=body_request)
    assert res.headers["ext_access_token"] == "qwertyu12345"
    assert res.json()["status"] == "please enter email"


def test_yandex_user_login():
    url = "http://auth:5000/auth/api/v1/yandex/yandex-login"
    send_url = f"https://www.dynfor.ru/#access_token=qwertyu0123456789&token_type=bearer&expires_in=31536000&test_case={settings.TEST_CASE}"
    body_request = {"url": send_url}
    res = requests.post(url, json=body_request)
    params["access_token"] = res.headers["access_token"]
    assert res.content.decode() == "Login succesful"
    assert res.headers["access_token"] is not None
    assert res.headers["refresh_token"] is not None


def test_yandex_user_set_email():
    url = "http://auth:5000/auth/api/v1/yandex/yandex-set-email"
    headers = {"ext_access_token": "qwertyu0123456789"}
    body_request = {"email": "yandex5@co.com",
                    "expires_in": "1286400",
                    "user_ext_id": "0123456789",
                    "ext_auth_source": "login.yandex.ru",
                    "test_case": settings.TEST_CASE_WITHOUT_EMAIL}
    res = requests.post(url, json=body_request, headers=headers)
    assert res.json()["status"] == "User  yandex5@co.com created"


def test_making_user_our(get_cursor):
    url_profile = requests.get("http://auth:5000/auth/api/v1/users/profile",
                               headers=params).json()
    url = "http://auth:5000/auth/api/v1" + url_profile["redirect"]
    body = {
        "password": "string",
        "login": "string",
        "is_active": True
    }
    res = requests.patch(url, json=body, headers=params)
    user_id = res.json()["user_id"]
    get_cursor.execute(f"SELECT ext_auth_source_id FROM users WHERE id = '{user_id}' ;")
    user = get_cursor.fetchone()
    assert user[0] is None
    assert res.json()["password"] == "has changed"
