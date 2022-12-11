from flask_wtf import FlaskForm, RecaptchaField


class ContactForm(FlaskForm):
    # text = StringField('Комментарий', validators=[DataRequired()])
    recaptcha = RecaptchaField()
