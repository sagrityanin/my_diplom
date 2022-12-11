users = {
            "email": "rokkimouse@yandex.ru",
            "password": "superpassword",
        },
        {
            "email": "sagrityanin@yandex.ru",
            "password": "superpassword",
        },
        {
            "email": "georgy.v.repin@gmail.com",
            "password": "superpassword",
        }

### Токен для админа можно получить:
    docker-compose -f docker-compose.yml  exec -it auth python tests/my_token.py

# Все дальнейшее актуально только при запуске через start.sh
### Токены для реальных пользователей можно получить через swagger:
    http://127.0.0.1:8068/auth/api/v1/
          раздел USERS -> /user/login
          емайл и пароль можно взять любой из users, который в начале файла

### Список пользователей с id можно получить через swagger:
    только с админским access_token
    http://127.0.0.1:8008/admin/api/v1/
        раздел user -> user/user-list