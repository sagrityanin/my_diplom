from flask import Flask
from flask_sqlalchemy import SQLAlchemy  # type: ignore

from core.config import settings  # type: ignore

db = SQLAlchemy()


def init_db(app: Flask):
    app.config[
        'SQLALCHEMY_DATABASE_URI'] = f'postgresql://{settings.AUTH_POSTGRES_USER}:{settings.AUTH_POSTGRES_PASSWORD}@{settings.AUTH_POSTGRES_HOST}:{settings.AUTH_POSTGRES_PORT}/{settings.AUTH_POSTGRES_DB}'
    app.config['SQLALCHEMY_TRACK_MODIFICATION'] = False
    db.init_app(app)
