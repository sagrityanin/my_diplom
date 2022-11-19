import uuid
from sqlalchemy.dialects.postgresql import UUID  # type: ignore

from db.postgres import db


class ExtAuth(db.Model):
    __table_args__ = {"schema": "customers"}
    __tablename__ = 'ext_auth'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    auth_source = db.Column(db.String(255), nullable=False)
    auth_source_url = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'<ExtAuth {self.auth_source}>'
