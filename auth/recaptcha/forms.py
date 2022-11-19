from flask_wtf import FlaskForm
from flask_wtf import RecaptchaField


class ContactForm(FlaskForm):
    # text = StringField('Комментарий', validators=[DataRequired()])
    recaptcha = RecaptchaField()
