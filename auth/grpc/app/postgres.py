import psycopg2
from psycopg2.extras import DictCursor
from config import settings

def get_conn():
    with psycopg2.connect(host=settings.AUTH_POSTGRES_HOST, user=settings.AUTH_POSTGRES_USER,
                            port=settings.AUTH_POSTGRES_PORT, password=settings.AUTH_POSTGRES_PASSWORD,
                            database=settings.AUTH_POSTGRES_DB, cursor_factory=DictCursor) as conn:
        return conn


def get_cursor(get_conn):
    cursor = get_conn.cursor()
    return cursor

connection = get_conn()
cursor = get_cursor(connection)