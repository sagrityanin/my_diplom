### Запуск

    docker-compose  up -d


Authorization module (Flask) test run:
    - docker-compose exec -it auth bash test_auth.sh
For adminfunctions test run
    - docker-compose exec -it admin bash test_admin.sh


# Для тестирования access токен можно получить командой:
get_token:
	docker-compose -f docker-compose.yml  exec -it auth python tests/my_token.py

# Просмотр логов ETL:
get_etl_logs:
	docker-compose docker-compose.yml up -d exec -it etl cat etl.log

