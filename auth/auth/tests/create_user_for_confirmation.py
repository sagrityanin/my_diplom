import requests
import uuid


user_email = "andrey@info66.ru"
user_uuid = uuid.uuid4()
# Get captcha token
url = "http://127.0.0.1:8088/auth/api/v1/token/token-get"
data = {
    "user_email": user_email,
    "user_id": str(user_uuid),
    "role": "unsubscriber",
    "type": "captcha"
}
res = requests.post(url, json=data)
print("captcha", res.content.decode())
captch_token = res.headers.get("access_token")
# print(captch_token)

# Make user
new_user_url = "http://127.0.0.1:8088/auth/api/v1/users/new-user"
headers = {"captcha_token": captch_token}
new_user_data = {
    "email": user_email,
    "password": "1234",
    "login": "user1"
}
res = requests.post(new_user_url, json=new_user_data, headers=headers)  # type: ignore
print(res.content.decode())
