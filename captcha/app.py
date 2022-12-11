import logging
import uuid

from core import token
from db.redis import redis_conn
from flask import Flask, Response, render_template, request
from flask_session_captcha import FlaskSessionCaptcha
from flask_sessionstore import Session

app = Flask(__name__)

app.config["SECRET_KEY"] = uuid.uuid4()
app.config["CAPTCHA_ENABLE"] = True
app.config["CAPTCHA_LENGTH"] = 5
app.config["CAPTCHA_WIDTH"] = 160
app.config["CAPTCHA_HEIGHT"] = 60
app.config["SESSION_REDIS"] = redis_conn
app.config["CAPTCHA_SESSION_KEY"] = "captcha_image"
app.config["SESSION_TYPE"] = "redis"

Session(app)

captcha = FlaskSessionCaptcha(app)


@app.route("/captcha/api/v1", methods=["POST", "GET"])
def index():
    if request.method == "POST":
        if captcha.validate():
            logging.info("Captcha correct")
            token_payload = {"type": "captcha"}
            current_token = token.TokenGet(token_payload)
            captcha_token = current_token.get_token()
            resp = Response("Captcha correct")
            resp.headers["captcha_token"] = captcha_token
            return resp
        else:
            return {"Captcha": "fail"}

    return render_template("form.html")


if __name__ == "__main__":
    app.debug = True
    logging.getLogger().setLevel("DEBUG")
    app.run()
