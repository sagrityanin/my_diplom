#!/bin/bash
docker compose -f docker-compose.test.yml up $1 -d

docker exec -it auth bash test_auth.sh

docker exec -it admin bash test_admin.sh

docker exec -it auth pytest -s -v tests/test_payment_logs.py