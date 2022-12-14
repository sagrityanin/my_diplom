import json
import logging
from datetime import datetime
from typing import Optional, Union
from urllib.parse import urlparse

import requests
from core.config import settings  # type: ignore
from db.postgres import db
from flask import Response
from models.ext_auth import ExtAuth
from models.roles import Roles
from models.users import Users
from w3lib.url import url_query_parameter


class ExtUser:
    def __init__(self, url_received: str):
        url = url_received.replace("#", "?")
        self.access_token = url_query_parameter(url, "access_token")
        self.user_ext_id = url_query_parameter(url, "user_id")
        self.email = url_query_parameter(url, "email")
        self.ext_auth_source = urlparse(url).netloc
        self.expires_in = int(url_query_parameter(url, "expires_in"))  # type: ignore
        self.test_case = url_query_parameter(url, "test_case")
        self.password = None

    def check_email(self) -> Optional[Response]:
        if self.email is None:
            resp = Response(json.dumps({"status": "please enter email", "user_ext_id": self.user_ext_id,
                                        "ext_auth_source": self.ext_auth_source}),
                            status=400, mimetype='application/json')
            resp.headers["ext_access_token"] = self.access_token  # type: ignore
            return resp
        return None

    def check_exists_user(self) -> bool:
        user = Users.query.filter_by(email=self.email).first()
        if user is not None:
            logging.info("user is busy")
            return True
        return False

    def create_ext_login_user(self) -> Response:
        time_created = str(datetime.now())
        roles = Roles.query.filter_by(role='unsubscriber').first()
        ext_auth_source = ExtAuth.query.filter_by(auth_source=self.ext_auth_source).first()

        try:
            new_user = Users(password=self.password, email=self.email,
                             created_at=time_created, role_id=roles.id, user_ext_id=self.user_ext_id,
                             ext_auth_source_id=ext_auth_source.id, is_active=True)
            db.session.add(new_user)
            db.session.commit()
            return Response(json.dumps({"status": f"User {self.email} created"}))

        except Exception:
            return Response(json.dumps({"status": f"User {self.email} NOT created"}),
                            status=400, mimetype='application/json')


class VkUser(ExtUser):
    def check_vk_user(self):
        url = f"https://api.vk.com/method/users.get?user_id={self.user_ext_id}&fields=nickname&access_token={self.access_token}&v=5.131"
        try:
            response = json.loads(requests.get(url).content)
            logging.info(f"request {response}")
            if "error" in response:
                return False
            if int(response['response'][0]["id"]) == int(self.user_ext_id):
                return True
            return False
        except Exception:
            return False


class YandexUser(ExtUser):
    def get_yandex_user_data(self) -> Union[str, bool]:
        if self.test_case == settings.TEST_CASE:
            self.email = "yandex_test@co.com"
            self.user_ext_id = "12345"
            return True

        elif self.test_case == settings.TEST_CASE_WITHOUT_EMAIL:
            self.user_ext_id = "0123456789"
            return True
        else:
            try:
                headers = {"Authorization": f"OAuth {self.access_token}"}
                request_url = "https://login.yandex.ru/info?format=json"
                b_response = requests.get(request_url, headers=headers)
                response = json.loads(b_response.content.decode())
                logging.info(f"default email {response['default_email']}")
                self.email = response["default_email"]
                self.user_ext_id = response["client_id"]
                return True
            except Exception:
                return "Bad token"
