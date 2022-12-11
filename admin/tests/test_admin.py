# flake8: noqa
import os

import psycopg2  # type: ignore
import pytest
import repackage  # type: ignore
import requests  # type: ignore
import sjwt

repackage.up()
from core.config import settings  # type: ignore

JWT_KEY = os.getenv("JWT_KEY")
payload = {"user_id": "my_user2", "type": "access_token", "role": "admin", "user_email": "test@co.com"}
params = {"access_token": sjwt.gettoken.get_token(JWT_KEY, **payload)}

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


def test_new_user_1(get_conn, get_cursor):
    get_cursor.execute("TRUNCATE users_logs;")
    get_cursor.execute("DELETE FROM users WHERE email LIKE '%co.com' ;")
    get_conn.commit()
    data = {
        "email": "test1@co.com",
        "password": "super",
        "login": ""
    }
    res = requests.post("http://127.0.0.1:5000/admin/api/v1/user/new-user", json=data).json()
    expected_response = "User test1@co.com created"
    assert res == expected_response


def test_new_user_repeat():
    data = {
        "email": "test1@co.com",
        "password": "super",
        "login": ""
    }
    res = requests.post("http://127.0.0.1:5000/admin/api/v1/user/new-user", json=data).json()
    expected_response = {"message": "User_name test1@co.com is busy"}
    assert res == expected_response


def test_new_user_2():
    data = {
        "email": "test2@co.com",
        "password": "super",
        "login": ""
    }
    res = requests.post("http://127.0.0.1:5000/admin/api/v1/user/new-user", json=data).json()
    expected_response = "User test2@co.com created"
    assert res == expected_response


def test_login_with_bad_password():
    data = {
        "user_email": "test2@co.com",
        "password": "12334"
    }
    res = requests.post("http://127.0.0.1:5000/admin/api/v1/user/login", json=data).json()
    expected_response = {"message": "Username password broken"}
    assert res == expected_response


def test_login_with_good_password(get_cursor, get_conn):
    get_cursor.execute("UPDATE users SET role_id = (SELECT id FROM roles WHERE role = 'admin') \
                        WHERE email = 'test1@co.com';")
    get_conn.commit()
    get_cursor.execute("SELECT id FROM users WHERE email = 'test1@co.com'; ")
    data = {
        "user_email": "test1@co.com",
        "password": "super"
    }
    resp = requests.post("http://127.0.0.1:5000/admin/api/v1/user/login", json=data)
    expected_response = "Login succesful"
    params["access_token"] = resp.headers["access_token"]
    params["refresh_token"] = resp.headers["refresh_token"]
    assert resp.text == expected_response


def test_get_profile_user1(get_cursor):
    get_cursor.execute("SELECT id FROM users WHERE email = 'test1@co.com'; ")
    user_id = get_cursor.fetchone()[0]
    params["user1_id"] = user_id
    user1_id = params["user1_id"]
    url = f"http://127.0.0.1:5000/admin/api/v1/user/{user1_id}/profile/"
    resp = requests.get(url, headers=params).json()
    assert resp["user_id"] == params["user1_id"]
    assert resp["email"] == "test1@co.com"


def test_get_user2_profile_by_user1_token(get_cursor):
    get_cursor.execute("SELECT id FROM users WHERE email = 'test1@co.com'; ")
    user2_id = get_cursor.fetchone()[0]
    params["user2_id"] = user2_id
    url = f"http://127.0.0.1:5000/admin/api/v1/user/{user2_id}/profile/"
    res = requests.get(url, headers=params).json()
    assert res["email"] == "test1@co.com"


def test_set_user2_profile_by_user1_token():
    user2_id = params["user2_id"]
    url = f"http://127.0.0.1:5000/admin/api/v1/user/{user2_id}/profile/"
    data = {
        "password": "",
        "login": "SuperLogin",
        "role": "subscriber",
        "is_active": True
    }
    resp = requests.patch(url, headers=params, json=data).json()
    assert resp["user_id"] == user2_id
    assert resp["login"] == "has changed"
    assert resp["password"] == "not changed"
    assert resp["role"] == "has changed"
    assert resp["is_active"] == "has changed"


def test_logout():
    url = "http://127.0.0.1:5000/admin/api/v1/user/logout"
    resp = requests.get(url, headers=params).json()
    assert resp["user_email"] == "test1@co.com"
    assert resp["status"] == "logout"


def test_get_users_list():
    url = "http://127.0.0.1:5000/admin/api/v1/user/users-list?sort_order=asc&sort_field=email&page_number=1&page_size=5"
    res = requests.get(url, headers=params).json()
    assert res["Users list"] == "has done"


def test_get_users_list_without_page_params():
    url = "http://127.0.0.1:5000/admin/api/v1/user/users-list"
    resp = requests.get(url, headers=params).json()
    assert resp == {'message': 'Page is not int or not exists'}


def test_get_logs():
    user_id = params["user1_id"]
    url = f"http://127.0.0.1:5000/admin/api/v1/user/user-login-logs/{user_id}?sort_order=asc&sort_field=user_agent&page_size=5&page_number=1"
    resp = requests.get(url, headers=params).json()
    assert resp["Total count page"] == 1
    assert resp["User logs list"] == "has done"
