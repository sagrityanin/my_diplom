import unittest
# from seleniumwire import webdriver
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.chrome.options import Options
from selenium.webdriver import DesiredCapabilities
import warnings
import requests
import sjwt
from time import sleep

payload = {
    "user_email": "string",
    "user_id": "string",
    "role": "admin",
    "type": "access_token"
}
JWT_KEY = "SuperPuperKey"
headers = {"access_token": sjwt.gettoken.get_token(JWT_KEY, **payload)}
params = {}


def get_user_id() -> str:
    url = "https://pycinema.ru:8443/admin/api/v1/user/users-list?sort_order=asc&sort_field=email&page_number=1&page_size=5"
    res = requests.get(url, headers=headers).json()
    params["user_id"] = list(filter(lambda x: x["email"] == "sagrityanin@yandex.ru", res["users"]))[0]["id"]
    params["email"] = "sagrityanin@yandex.ru"
    payload = {"user_id": params["user_id"], "type": "access_token", "role": "unsubscriber",
               "user_email": params["email"]}
    params["access_token"] = sjwt.gettoken.get_token(JWT_KEY, **payload)
    new_headers = {"Authorization": f"Bearer {sjwt.gettoken.get_token(JWT_KEY, **payload)}"}
    params["headers"] = new_headers
    assert res["Users list"] == "has done"
    return params["user_id"]


def get_price():
    price_url = "https://pycinema.ru:8443/admin/api/v1/price/"
    res = requests.get(price_url, headers=headers).json()
    price_id = res[4]["id"]
    return price_id


def test_pay_widget():
    driver = webdriver.Firefox()
    # driver = webdriver.Chrome()
    warnings.simplefilter("ignore", ResourceWarning)

    url = "https://pycinema.ru/index.html"
    driver.get(url)
    email = driver.find_elements(By.ID, 'floatingInput')[0]
    password = driver.find_elements(By.ID, 'floatingPassword')[0]
    assert email is not None
    assert password is not None
    email.send_keys("sagrityanin@yandex.ru")
    password.send_keys("superpassword")
    submit = driver.find_element(By.ID, "login")
    submit.click()
    sleep(5)
    price_id = get_price()
    print("price_id", price_id)
    order = driver.find_elements(By.ID, price_id)[0]
    assert order is not None
    order.click()
    sleep(1)
    no_renewal = driver.find_elements(By.TAG_NAME, "button")[-1]
    no_renewal.click()
    sleep(1)
    
    iframe = driver.find_elements(By.TAG_NAME, "iframe")[0]
    
    assert iframe is not None
    driver.switch_to.frame(iframe)
    sleep(2)
    card = driver.find_element(By.NAME, "card")
    date = driver.find_element(By.NAME, "date")
    cvv = driver.find_element(By.NAME, "cvv")
    assert card is not None
    assert date is not None
    assert cvv is not None
    card.send_keys("4242424242424242")
    date.send_keys("0125")
    cvv.send_keys("005")
    sleep(2)
    submit = driver.find_element(By.TAG_NAME, "button")
    submit.click()
    sleep(15)
    pass
    print("pay widget success")

    print()
    print("Start check order status")
    get_user_id()
    url = "https://pycinema.ru/api/v1/subcriptions/my/subscription/"

    for i in range(120):
        res = requests.get(url, headers=params["headers"]).json()
        print(i)
        if "subscription" in res and res["subscription"]["payment_status"] == "payment_completed":
            assert res["subscription"]["payment_status"] == "payment_completed"
            break
        sleep(5)
    driver.close()

if __name__ == "__main__":
    unittest.main()
