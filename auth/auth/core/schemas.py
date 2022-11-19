from flask_restx import fields  # type: ignore
from models.users import Users
from models.users_logs import UsersLogs

authorizations = {
    'access_token': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'access_token'
    },
    'refresh_token': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'refresh_token'
    },
    'vk_access_token': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'vk_access_token'
    },
    'captcha_token': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'captcha_token'
    },
}

model_payment_log = {
    "id": fields.String(required=True, description="UUID"),
    "subscription_id": fields.String(required=True, description="UUID"),
    "event_time": fields.String(),
    "provider": fields.String(required=True),
    "status": fields.String(required=True),
    "raw": fields.String()
}

model_payload = {
    "user_email": fields.String(required=True),
    "user_id": fields.String(required=True, description="UUID"),
    "role": fields.String(required=True, enum=["unsubscriber", "superuser", "admin", "subscriber"],
                          default="unsubscriber"),
    "type": fields.String(required=True, enum=["access", "refresh"], default="access")
}
model_token = {
    "token": fields.String(required=True)
}
model_user = {
    "email": fields.String(required=True),
    "password": fields.String(required=True),
    "login": fields.String(default="")
}
model_user_login = {
    "user_email": fields.String(required=True),
    "password": fields.String(required=True)
}
model_profile = {
    "password": fields.String(required=False, default=None),
    "login": fields.String(required=False, default=None),
    "role": fields.String(required=False, enum=["unsubscriber", "superuser", "admin", "subscriber"],
                          default="unsubscriber"),
    "is_active": fields.Boolean(default=True),
    "email_notification": fields.Boolean(description="Users notification by email"),
    "ws_notification": fields.Boolean(description="Users notification by WebSockets")
}


# response models
model_token_payload_response = {
    "user_email": fields.String(description="Email of the user"),
    "user_id": fields.String(description="UUID"),
    "role": fields.String(enum=["unsubscriber", "superuser", "admin", "subscriber"], description="Users role"),
    "type": fields.String(required=True, enum=["access", "refresh"], description="Type of the token"),
    "iat": fields.Float(),
    "exp": fields.Float(),
    "Check_token": fields.Boolean(description="Check if the token is valid")
}
model_response_users_profile = {
    "user_email": fields.String(description="Email of the user"),
    "redirect": fields.String(description="Path to the user")
}
model_response_users_id_profile_response_post = {
    "user_id": fields.String(description="UUID"),
    "login": fields.String(description="Users login"),
    "password": fields.String(description="Users password"),
    "role": fields.String(enum=["unsubscriber", "superuser", "admin", "subscriber"], description="Users role"),
    "is_active": fields.Boolean(description="Users status"),
    "email_notification": fields.Boolean(description="Users notification by email"),
    "ws_notification": fields.Boolean(description="Users notification by WebSockets")
}
model_response_users_id_profile_response_get = {
    "user_id": fields.String(description="UUID"),
    "email": fields.String(description="Email of the user"),
    "role": fields.String(enum=["unsubscriber", "superuser", "admin", "subscriber"], description="Users role"),
    "created_at": fields.String(description="Email of the user"),
    "updated_at": fields.String(description="Email of the user"),
    "is_active": fields.Boolean(description="Users status"),
    "email_notification": fields.Boolean(description="Users notification by email"),
    "ws_notification": fields.Boolean(description="Users notification by WebSockets")
}
model_response_users_list_nested_user_row = {
    "email": fields.String(description="Email of the user"),
    "id": fields.String(description="UUID"),
    "role": fields.String(enum=["unsubscriber", "superuser", "admin", "subscriber"], description="Users role"),
    "login": fields.String(description="Users login")
}


# error models
model_response_400_401_403_404_base = {
    "message": fields.String(description="Error message")
}

model_response_400_need_email = {
    "status": fields.String(description="Error message"),
    "user_ext_id": fields.String(description="user id from external authentication provider"),
    "ext_auth_source": fields.String(description="external authentication provider")
}

model_vk_user = {
    "url": fields.String(required=True),
}
model_set_email_user = {
    "email": fields.String(required=True),
    "expires_in": fields.String(required=True),
    "user_ext_id": fields.String(required=True),
    "ext_auth_source": fields.String(required=True)
}

users_sort_field_dict = {"email": Users.email, "login": Users.login}
sort_order_list = ["asc", "desc"]
users_logs_sort_field_dict = {"user_agent": UsersLogs.user_id, "created_at": UsersLogs.created_at}
