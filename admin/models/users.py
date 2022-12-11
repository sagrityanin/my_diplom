import uuid
from datetime import datetime

from db.postgres import db
from sqlalchemy import UniqueConstraint  # type: ignore
from sqlalchemy.dialects.postgresql import UUID  # type: ignore


def create_partition(target, connection, **kw) -> None:
    """ creating partition by users """
    connection.execute(
        """CREATE TABLE customers.users_is_active PARTITION OF customers.users for values in (true);"""
    )
    connection.execute(
        """CREATE TABLE customers.users_is_not_active PARTITION OF customers.users for values in (false);"""
    )


class Users(db.Model):
    __tablename__ = 'users'
    __table_args__ = (
        UniqueConstraint('id', 'is_active'),
        UniqueConstraint('email', 'is_active'),
        {
            "schema": "customers",
            'postgresql_partition_by': 'LIST (is_active)',
            'listeners': [('after_create', create_partition)],
        }
    )

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    login = db.Column(db.String)
    password = db.Column(db.String, nullable=False)
    email = db.Column(db.String(64))
    created_at = db.Column(db.String, nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    deleted_at = db.Column(db.DateTime, nullable=True)
    role_id = db.Column(UUID(as_uuid=True), db.ForeignKey('customers.roles.id'), nullable=False)
    user_ext_id = db.Column(db.String, nullable=True)
    ext_auth_source_id = db.Column(UUID(as_uuid=True), db.ForeignKey('customers.ext_auth.id'), nullable=True)
    is_active = db.Column(db.Boolean, primary_key=True, nullable=False)
    email_notification = db.Column(db.Boolean, default=False)
    ws_notification = db.Column(db.Boolean, default=False)
    confirm_email_status = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.email}>'
