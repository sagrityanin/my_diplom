import os

import sjwt  # type: ignore

JWT_KEY = os.getenv("JWT_KEY")
payload = {"user_id": "f10ffac8-0a4d-4305-ab29-85505dae0380", "type": "access_token",
           "role": "admin", "user_email": "test@co.com"}
ac_token = sjwt.gettoken.get_token(JWT_KEY, **payload)
print("access_token:", ac_token)
payload["type"] = "refresh_token"
ref_token = sjwt.gettoken.get_token(JWT_KEY, **payload)
print("refresh_token:", ref_token)
