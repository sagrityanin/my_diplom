# flake8: noqa
import requests
import repackage # type: ignore

repackage.up()
from core.config import settings # type: ignore


def test_vk_user_create():
    url = "http://auth:5000/auth/api/v1/vk-com/vk-create-user"
    send_url = f"https://oauth.vk.com/blank.html#access_token=vk1.a.qwertyasdfgh&expires_in=1286400&user_id=12345&email=vk_user@co.com&test_case={settings.TEST_CASE}"
    body_request = {"url": send_url}
    res = requests.post(url, json=body_request)
    assert res.json()["status"] == "User vk_user@co.com created"


def test_vk_user_create_without_email():
    url = "http://auth:5000/auth/api/v1/vk-com/vk-create-user"
    send_url = f"https://oauth.vk.com/blank.html#access_token=vk1.a.qwertyasdfgh&expires_in=1286400&user_id=12345&test_case={settings.TEST_CASE}"
    body_request = {"url": send_url}
    res = requests.post(url, json=body_request)
    assert res.headers["ext_access_token"] == "vk1.a.qwertyasdfgh"
    assert res.json()["status"] == "please enter email"


def test_vk_user_login():
    url = "http://auth:5000/auth/api/v1/vk-com/vk-login"
    send_url = f"https://oauth.vk.com/blank.html#access_token=vk1.a.qwertyasdfgh&expires_in=1286400&user_id=12345&email=vk_user@co.com&test_case={settings.TEST_CASE}"
    body_request = {"url": send_url}
    res = requests.post(url, json=body_request)
    assert res.content.decode() == "Login succesful"
    assert res.headers["access_token"] is not None
    assert res.headers["refresh_token"] is not None


def test_vk_user_set_email():
    url = "http://auth:5000/auth/api/v1/vk-com/vk-set-email"
    headers = {"vk_access_token": "vk1.a.qwertyasdfgh"}
    body_request = {"email": "test5@co.com",
                    "expires_in": "1286400",
                    "user_ext_id": "3713405",
                    "ext_auth_source": "oauth.vk.com",
                    "test_case": settings.TEST_CASE}
    res = requests.post(url, json=body_request, headers=headers)
    assert res.json()["status"] == "User test5@co.com created"
