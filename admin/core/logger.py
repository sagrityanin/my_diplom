import logging
import os
from logging.handlers import RotatingFileHandler

from flask import has_request_context, request

LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

LOG_DEFAULT_HANDLERS = ['console', ]
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': LOG_FORMAT
        },
    },
    'handlers': {
        'console': {
            'level': LOG_LEVEL,
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': {'level': LOG_LEVEL,
                 'class': 'logging.FileHandler',
                 'filename': 'auth.log',
                 'mode': 'w',
                 'formatter': 'verbose'
        }
    },
    'loggers': {
        '': {
            'handlers': LOG_DEFAULT_HANDLERS,
            'level': LOG_LEVEL,
        },
    },
    'root': {
        'level': LOG_LEVEL,
        'formatter': 'verbose',
        'handlers': LOG_DEFAULT_HANDLERS,
    },
}


class RequestFormatter(logging.Formatter):
    def format(self, record):
        if has_request_context():
            record.url = request.url
            record.remote_addr = request.remote_addr
            record.request_id = request.headers.get('X-Request-Id')
        else:
            record.url = None
            record.remote_addr = None
        return super().format(record)


def file_logger():
    file_hand = RotatingFileHandler('/home/flask/logs/admin.log', maxBytes=1000000,
                                    backupCount=10)
    file_hand.setFormatter(RequestFormatter('%(request_id)s admin %(url)s  %(message)s '))
    file_hand.setLevel(logging.INFO)
    return file_hand


file_handler = file_logger()
