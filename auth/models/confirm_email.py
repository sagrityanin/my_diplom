from datetime import datetime

from db.postgres import db
from sqlalchemy.dialects.postgresql import UUID  # type: ignore


class ConfirmEmail(db.Model):
    __table_args__ = {"schema": "customers"}
    __tablename__ = 'confirm_email'

    id = db.Column(UUID(as_uuid=True), primary_key=True, nullable=False)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('customers.users.id'))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    exp_confirm_email = db.Column(db.DateTime)

    def __repr__(self):
        return f'<ConfirmEmail {self.id}>'
