import json

import repackage  # type: ignore
import requests
import sjwt

repackage.up()
from core.config import settings  # type: ignore

payload = {"user_id": "0admin19-7ide-43cf-b9c8-31cb3e6698f4", "type": "access_token", "role": "admin",
           "user_email": "test@co.com"}
the_token = sjwt.gettoken.get_token(settings.JWT_KEY, **payload)
url = "http://127.0.0.1:5000/admin/api/v1/price/"
headers = {"access_token": the_token}
users = []


def test_get_delete():
    response = requests.get(url, headers=headers)
    for row in json.loads(response.content):
        arg = {"price_id": row["id"]}
        row_response = requests.delete(url, headers=headers, params=arg)
        expected_answer = f"Price record with id = {row['id']} disable"
        assert json.loads(row_response.content) == expected_answer


def test_create_price():
    prices = [{"duration": 1, "price": 100, "currency": "rub"},
              {"duration": 7, "price": 200, "currency": "rub"},
              {"duration": 14, "price": 350, "currency": "rub"},
              {"duration": 30, "price": 500, "currency": "rub"},
              {"duration": 0.001388889, "price": 50, "currency": "rub"}]
    for price in prices:
        result = requests.put(url, headers=headers, json=price)
        expected_row = f"Set price record {price['duration']}"
        assert expected_row in json.loads(result.content)


def test_get_price():
    res = requests.get(url, headers=headers).json()
    for record in res:
        if record["duration"] == 7:
            assert record["price"] == 200
        if record["duration"] == 14:
            assert record["price"] == 350


def test_set_promo():
    url2 = "http://127.0.0.1:5000/admin/api/v1/user/users-list?sort_order=asc&sort_field=email&page_number=1&page_size=5"
    res = requests.get(url2, headers=headers).json()
    response = requests.get(url, headers=headers).json()
    price_id_1 = list(filter(lambda x: x["duration"] == 1, response))[0]["id"]
    url_promo = "http://127.0.0.1:5000/admin/api/v1/promo-subscribtion/set-promo"
    assert res["Users list"] == "has done"
    for user in res["users"]:
        users.append(user["id"])
        response = requests.put(url_promo, headers=headers, json={"price_id": price_id_1,
                                                                  "users": [user["id"], ]}).json()
        assert response["price_id"] == price_id_1
        assert response["users_set_price"][0] == user["id"]
