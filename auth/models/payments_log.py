import uuid

from db.postgres import db
from sqlalchemy.dialects.postgresql import JSON, UUID  # type: ignore


class PaymentsLog(db.Model):
    __tablename__ = 'payments_log'
    __table_args__ = {"schema": "customers"}

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    subscription_id = db.Column(UUID(as_uuid=True), db.ForeignKey('customers.subscribtion.id'), nullable=False)
    event_time = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)
    provider = db.Column(db.String, nullable=False)
    status = db.Column(db.String, nullable=False)
    raw = db.Column(JSON)

    def __repr__(self):
        return f'<PaymentsLog {self.id}>'
