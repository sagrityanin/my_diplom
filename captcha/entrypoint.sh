#!/bin/bash

echo "Start app"
gunicorn --workers 5 --bind 0.0.0.0:5000 wsgi:app
echo "App started"

#exec "$@