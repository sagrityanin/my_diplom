#!/bin/bash

service filebeat start

#echo "Migrate db"
#flask db upgrade
#echo "Migration ended"

echo "Start app"
gunicorn --workers 5 --bind 0.0.0.0:5000 wsgi:app
echo "App started"

exec "$@
