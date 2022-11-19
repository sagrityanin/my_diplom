# flake8: noqa
import requests  # type: ignore
import psycopg2  # type: ignore
import pytest
import token_test

import repackage # type: ignore

repackage.up()
from core.config import settings # type: ignore

params = {}


def get_captcha_token():
    token_payload = {"type": "captcha"}
    current_token = token_test.TokenGet(token_payload)
    captcha_token = current_token.get_token()

    return captcha_token


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


def new_users():
    conn = psycopg2.connect(host=settings.AUTH_POSTGRES_HOST, user=settings.AUTH_POSTGRES_USER,
                            password=settings.AUTH_POSTGRES_PASSWORD,
                            database=settings.AUTH_POSTGRES_DB)
    cursor = conn.cursor()
    # get_cursor.execute("TRUNCATE users_logs;")
    # get_cursor.execute("DELETE FROM users WHERE email LIKE '%co.com' ;")
    # get_conn.commit()
    captcha_token = get_captcha_token()
    headers = {"captcha_token": captcha_token}
    for i in range(1000):
        data = {
            "email": f"test{i}@test.com",
            "password": "superpassword",
            "login": ""
        }
        res = requests.post("http://localhost:5000/auth/api/v1/users/new-user", json=data,
                            headers=headers).json()
        print(i)
    cursor.execute("UPDATE users SET email_notification = TRUE, ws_notification = TRUE \
                                WHERE email_notification = FALSE;")
    conn.commit()

new_users()
