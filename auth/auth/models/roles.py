import uuid
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID  # type: ignore

from db.postgres import db


class Roles(db.Model):
    __table_args__ = {"schema": "customers"}
    __tablename__ = 'roles'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    role = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    deleted_at = db.Column(db.DateTime)

    def __repr__(self):
        return f'<Role {self.role}>'
