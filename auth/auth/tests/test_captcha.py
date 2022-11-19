from http import HTTPStatus
import requests  # type: ignore


def test_captcha():
    url = "http://captcha:5000/captcha/api/v1"
    res = requests.get(url)
    assert res.status_code == HTTPStatus.OK
