import uuid
from sqlalchemy.dialects.postgresql import UUID  # type: ignore
from enum import Enum

from db.postgres import db


class Currency(Enum):
    dollar = "$"
    rub = "rub"


class Price(db.Model):
    __tablename__ = 'price'
    __table_args__ = {"schema": "customers"}

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    duration = db.Column(db.Integer, nullable=False)
    price = db.Column(db.FLOAT, nullable=False)
    currency = db.Column(db.Enum(Currency), default=Currency.rub, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)
    admin_id = db.Column(db.String, nullable=False)
    is_active = db.Column(db.Boolean, nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=db.func.current_timestamp(), nullable=False)

    def __repr__(self):
        return f'<Price {self.duration} day {self.price} {self.currency}>'
