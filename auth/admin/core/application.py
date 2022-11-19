import uuid
from flask import Flask
from flask_sessionstore import Session  # type: ignore
from db.redis import redis_conn

app = Flask(__name__)
app.config["SECRET_KEY"] = uuid.uuid4()
app.config['CAPTCHA_ENABLE'] = True
app.config['CAPTCHA_LENGTH'] = 5
app.config['CAPTCHA_WIDTH'] = 160
app.config['CAPTCHA_HEIGHT'] = 60
app.config['SESSION_REDIS'] = redis_conn
app.config['CAPTCHA_SESSION_KEY'] = 'captcha_image'
app.config['SESSION_TYPE'] = "redis"
Session(app)
