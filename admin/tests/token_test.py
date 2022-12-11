import base64
import hashlib
import hmac
import json
from datetime import datetime

import repackage  # type: ignore

repackage.up()
from core.config import settings  # type: ignore


class Token:

    def encode_array(self, array: dict) -> str:
        url = json.dumps(array)
        url_bytes = url.encode('utf-8')
        encoded = base64.b64encode(url_bytes)
        return encoded  # type: ignore

    def encode_headers_payloads(self) -> None:
        self.encode_headers = self.encode_array(self.headers)  # type: ignore
        self.encode_payload = self.encode_array(self.payload)  # type: ignore
        return None

    def decode_string(self) -> dict:
        data = base64.b64decode(self.encode_payload)
        res = json.loads(data.decode('utf-8'))
        return res

    def get_sign(self) -> str:
        key_s = settings.JWT_KEY
        key = key_s.encode('utf-8')
        source = self.encode_headers + self.encode_payload
        sign = hmac.new(key, source, hashlib.sha256)  # type: ignore
        return sign.hexdigest()


class TokenGet(Token):
    def __init__(self, payload):
        self.headers = {"alg": "HS256", "typ": "JWT"}
        self.payload = payload
        self.payload['iat'] = datetime.now().timestamp()
        if self.payload['type'] == 'refresh':
            self.payload['exp'] = datetime.now().timestamp() + settings.TTL_REFRESH_TOKEN
        elif self.payload['type'] == 'access':
            self.payload['exp'] = datetime.now().timestamp() + settings.TTL_ACCESS_TOKEN
        elif self.payload['type'] == 'captcha':
            self.payload['exp'] = datetime.now().timestamp() + settings.TTL_CAPTCHA_TOKEN

    def get_token(self) -> str:
        self.encode_headers_payloads()
        sign = self.get_sign()
        return self.encode_headers.decode('utf-8') + '.' + self.encode_payload.decode('utf-8') + '.' + sign  # type: ignore


class TokenCheck(Token):
    def __init__(self, token):
        self.token = token
        try:
            token_list = self.token.strip().split('.')
            self.encode_headers = token_list[0]
            self.encode_payload = token_list[1]
            self.sign = token_list[2]
        except Exception:
            self.encode_headers = False
            self.encode_payload = False

    def get_sign_for_check(self) -> str:
        key_s = settings.JWT_KEY
        key = key_s.encode('utf-8')
        source = self.encode_headers.encode('utf-8') + self.encode_payload.encode('utf-8')
        sign = hmac.new(key, source, hashlib.sha256)
        return sign.hexdigest()

    def check_token(self) -> True | False:  # type: ignore
        current_time = datetime.now().timestamp()
        try:
            sign = self.get_sign_for_check()
            payload = self.decode_string()
            if sign != self.sign:
                return "sign broken"
            if payload['exp'] <= current_time:
                return "time out"
            return True
        except Exception:
            return False

    def get_payload(self) -> dict:
        result = self.decode_string()
        result["Check_token"] = self.check_token()
        return result
