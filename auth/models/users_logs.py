import uuid
from datetime import datetime

from db.postgres import db
from sqlalchemy.dialects.postgresql import UUID  # type: ignore


class UsersLogs(db.Model):
    __tablename__ = 'users_logs'
    __table_args__ = (
        {
            "schema": "customers"
        }
    )

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    user_id = db.Column(UUID(as_uuid=True), nullable=False)
    user_agent = db.Column(db.String(255))
    user_action = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'<User_id {self.user_id}>'
