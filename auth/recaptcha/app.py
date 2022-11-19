import logging
from flask import Flask, request, Response, render_template
# from flask import request
# from flask import render_template
#  форма с валидацией и капчей
from forms import ContactForm
from core import token
from core.config import settings

app = Flask(__name__)
app.config['SECRET_KEY'] = settings.SECRET_KEY

#  ключи recaptcha от google
app.config['RECAPTCHA_PUBLIC_KEY'] = settings.RECAPTCHA_PUBLIC_KEY
app.config['RECAPTCHA_PRIVATE_KEY'] = settings.RECAPTCHA_PRIVATE_KEY


@app.route('/recaptcha/api/v1', methods=['GET', 'POST'])
def index():
    form = ContactForm()
    msg = ""
    if request.method == "POST":
        if form.validate_on_submit():
            logging.info("Captcha correct")
            token_payload = {"type": "captcha"}
            current_token = token.TokenGet(token_payload)
            captcha_token = current_token.get_token()
            resp = Response("Captcha correct")
            resp.headers["captcha_token"] = captcha_token
            return resp
        else:
            msg = "Ошибка валидации"

    return render_template("index.html",
                           title="index page",
                           form=form,
                           msg=msg)


if __name__ == '__main__':
    app.run(debug=True)
