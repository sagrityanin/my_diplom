"""adding roles to the table roles

Revision ID: 7d022738afb7
Revises: a26ccac2683f
Create Date: 2022-08-14 05:29:13.578746

"""
from alembic import op

from models.roles import Roles
from models.ext_auth import ExtAuth
# from model.price import Price
# from model.subscibtion import Subsribtion
from core.config import settings  # type: ignore

# revision identifiers, used by Alembic.
revision = '7d022738afb7'
down_revision = 'a26ccac2683f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.bulk_insert(
        Roles.__table__, [
            {'role': 'superuser'},
            {'role': 'admin'},
            {'role': 'subscriber'},
            {'role': 'unsubscriber'}
        ]
    )

    op.bulk_insert(
        ExtAuth.__table__, [
            {"auth_source": "oauth.vk.com",
             "auth_source_url": f"https://oauth.vk.com/authorize?client_id={settings.APP_VK_ID}&display=page&redirect_uri=https://oauth.vk.com/blank.html&scope=friends,email&response_type=token&v=5.131"
             },
            {"auth_source": "login.yandex.ru",
             "auth_source_url": "http://login.yandex.ru"}
        ]
    )

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    pass
    # ### end Alembic commands ###
