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


def test_new_user_1(get_conn, get_cursor):
    get_cursor.execute("TRUNCATE users_logs;")
    get_cursor.execute("TRUNCATE subscribtion;")
    get_cursor.execute("DELETE FROM users WHERE email LIKE '%co.com' ;")
    get_conn.commit()
    data = [{
            "email": "test1@co.com",
            "password": "pas",
            "login": ""
        }
    ]
    captcha_token = get_captcha_token()
    headers = {"captcha_token": captcha_token}
    for user in data:
        res = requests.post("http://auth:5000/auth/api/v1/users/new-user", json=user,
                            headers=headers).json()
    expected_response = "User test1@co.com created, Test email fack sended"
    assert res == expected_response


def test_new_user_repeat():
    data = {
        "email": "test1@co.com",
        "password": "pas",
        "login": ""
    }
    captcha_token = get_captcha_token()
    headers = {"captcha_token": captcha_token}
    res = requests.post("http://auth:5000/auth/api/v1/users/new-user",
                        headers=headers, json=data).json()
    expected_response = {"message": "User_name test1@co.com is busy"}
    assert res == expected_response


def test_new_user_2():
    data = {
        "email": "test2@co.com",
        "password": "super",
        "login": ""
    }
    captcha_token = get_captcha_token()
    headers = {"captcha_token": captcha_token}
    res = requests.post("http://auth:5000/auth/api/v1/users/new-user",
                        headers=headers, json=data).json()
    expected_response = "User test2@co.com created, Test email fack sended"
    assert res == expected_response


def test_login_with_bad_password():
    data = {
        "user_email": "test2@co.com",
        "password": "12334"
    }
    captcha_token = get_captcha_token()
    headers = {"captcha_token": captcha_token}
    res = requests.post("http://auth:5000/auth/api/v1/users/login",
                        headers=headers, json=data).json()
    expected_response = {"message": "Username password broken"}
    assert res == expected_response


def test_login_with_good_password():
    data = {
        "user_email": "test1@co.com",
        "password": "super"
    }
    captcha_token = get_captcha_token()
    headers = {"captcha_token": captcha_token}
    resp = requests.post("http://auth:5000/auth/api/v1/users/login",
                         headers=headers, json=data)
    expected_response = "Login succesful"
    params["access_token"] = resp.headers["access_token"]
    params["refresh_token"] = resp.headers["refresh_token"]
    assert resp.text == expected_response


def test_get_link_to_profile(get_cursor):
    get_cursor.execute("SELECT id FROM users WHERE email = 'test1@co.com'; ")
    user_id = get_cursor.fetchone()[0]
    params["user1_id"] = user_id
    get_cursor.execute("SELECT id FROM users WHERE email = 'test2@co.com'; ")
    user_id = get_cursor.fetchone()[0]
    params["user2_id"] = user_id
    resp = requests.get("http://auth:5000/auth/api/v1/users/profile", headers=params).json()
    assert resp["user_email"] == "test1@co.com"
    assert resp["redirect"] == f"/users/{params['user1_id']}/profile/"


def test_get_profile_user1():
    user1_id = params["user1_id"]
    url = f"http://auth:5000/auth/api/v1/users/{user1_id}/profile/"
    resp = requests.get(url, headers=params).json()
    assert resp["user_id"] == params["user1_id"]
    assert resp["email"] == "test1@co.com"


def test_get_user2_profile_by_user1_token():
    user2_id = params["user2_id"]
    url = f"http://auth:5000/auth/api/v1/users/{user2_id}/profile/"
    res = requests.get(url, headers=params).json()
    assert res == {'message': 'Token broken'}


def test_set_user2_profile_by_user1_token():
    user2_id = params["user2_id"]
    url = f"http://auth:5000/auth/api/v1/users/{user2_id}/profile/"
    data = {
        "password": "",
        "login": "SuperLogin",
        "role": "admin",
        "is_active": True
    }
    resp = requests.patch(url, headers=params, json=data).json()
    assert resp["token"] == "broken"


def test_set_self_profile():
    user1_id = params["user1_id"]
    url = f"http://auth:5000/auth/api/v1/users/{user1_id}/profile/"
    data = {
        "password": "",
        "login": "retin",
        "role": "admin",
        "is_active": False
    }
    resp = requests.patch(url, headers=params, json=data).json()
    assert resp["login"] == "has changed"
    assert resp["password"] == "not changed"
    assert resp["is_active"] == "not changed"
    assert resp["user_id"] == user1_id
    assert resp["role"] == "not changed"


def test_reissue_token():
    url = "http://auth:5000/auth/api/v1/token/token-reissue"
    resp = requests.get(url, headers=params)
    access_token = resp.headers["access_token"]
    refresh_token = resp.headers["refresh_token"]
    if access_token is None:
        assert 4 == 6
    if refresh_token is None:
        assert 2 == 4
    assert resp.text == "Token generated"


def test_logout():
    url = "http://auth:5000/auth/api/v1/users/logout"
    resp = requests.get(url, headers=params).json()
    assert resp["user_email"] == "test1@co.com"
    assert resp["status"] == "logout"


def test_reissue_token_after_logout():
    url = "http://auth:5000/auth/api/v1/token/token-reissue"
    res = requests.get(url, headers=params).json()
    user1_id = params["user1_id"]
    expected_response = f"User {user1_id} has logout"
    assert res["message"] == expected_response


#
def test_set_self_profile_with_broken_token():
    params["access_token"] = params["access_token"] + "qwerty"
    user_id = params["user1_id"]
    url = f"http://auth:5000/auth/api/v1/users/{user_id}/profile/"
    data = {
        "password": "",
        "login": "SuperLogin",
        "role": "admin",
        "is_active": False
    }
    resp = requests.patch(url, headers=params, json=data).json()
    assert resp["token"] == "broken"


def test_login_with_admin_access(get_cursor, get_conn):
    get_cursor.execute("UPDATE users SET role_id = (SELECT id FROM roles WHERE role = 'admin') \
                        WHERE email = 'test1@co.com';")
    get_cursor.execute("UPDATE users SET email_notification = TRUE, ws_notification = TRUE \
                            WHERE email_notification = FALSE;")
    get_conn.commit()
    data = {
        "user_email": "test1@co.com",
        "password": "super"
    }
    captcha_token = get_captcha_token()
    headers = {"captcha_token": captcha_token}
    resp = requests.post("http://auth:5000/auth/api/v1/users/login",
                         headers=headers, json=data)
    expected_response = "Login succesful"
    params["access_token"] = resp.headers["access_token"]
    params["refresh_token"] = resp.headers["refresh_token"]
    assert resp.text == expected_response


def test_get_user2_profile_by_user1_token_by_admin_access():
    user_id = params["user2_id"]
    url = f"http://auth:5000/auth/api/v1/users/{user_id}/profile/"
    resp = requests.get(url, headers=params).json()
    assert resp["message"] == "Token broken"


def test_set_user2_profile_by_user1_token_with_admin_access():
    user_id = params["user2_id"]
    url = f"http://auth:5000/auth/api/v1/users/{user_id}/profile/"
    data = {
        "password": "pas",
        "login": "SuperLogin",
        "role": "subscriber",
        "is_active": False
    }
    resp = requests.patch(url, headers=params, json=data).json()
    assert resp["token"] == "broken"


def test_get_user2_profile_by_user1_token_with_admin_access():
    user_id = params["user2_id"]
    url = f"http://auth:5000/auth/api/v1/users/{user_id}/profile/"
    resp = requests.get(url, headers=params).json()
    assert resp["message"] == "Token broken"


def test_login_with_superuser_access(get_cursor, get_conn):
    user_id = params["user2_id"]
    url = f"http://auth:5000/auth/api/v1/users/{user_id}/profile/"
    data = {
        "password": "super",
        "is_active": True
    }
    requests.post(url, headers=params, json=data)
    get_cursor.execute("UPDATE users SET role_id = (SELECT id FROM roles WHERE role = 'superuser') \
                        WHERE email = 'test2@co.com';")
    get_conn.commit()
    data = {
        "user_email": "test2@co.com",
        "password": "super"
    }
    captcha_token = get_captcha_token()
    headers = {"captcha_token": captcha_token}
    resp = requests.post("http://auth:5000/auth/api/v1/users/login",
                         headers=headers, json=data)
    expected_response = "Login succesful"
    params["access_token"] = resp.headers["access_token"]
    params["refresh_token"] = resp.headers["refresh_token"]
    assert resp.text == expected_response


def test_set_profile_admin_role_by_superuser():
    user_id = params["user2_id"]
    url = f"http://auth:5000/auth/api/v1/users/{user_id}/profile/"
    data = {
        "password": "123456",
        "login": "Super",
        "role": "admin",
        "is_active": False
    }
    resp = requests.patch(url, headers=params, json=data).json()
    assert resp["user_id"] == user_id
    assert resp["login"] == "has changed"
    assert resp["password"] == "has changed"
    assert resp["role"] == "has changed"
    assert resp["is_active"] == "has changed"


def test_get_logs():
    user_id = params["user1_id"]
    url = f"http://auth:5000/auth/api/v1/users/user-login-logs/{user_id}?sort_order=asc&sort_field=user_agent&page_size=5&page_number=1"
    resp = requests.get(url, headers=params).json()
    assert resp["Total count page"] == 1
    assert resp["User logs list"] == "has done"
