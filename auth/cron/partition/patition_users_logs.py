import psycopg2
from psycopg2.extras import DictCursor
import time
import datetime

from logger_partition import set_logs
import repackage

repackage.up()
import backoff
from config import settings

STEP = 100
PAUSE = 60 * 60 * 24


@backoff.backoff()
def partition_start():
    set_logs(f"partition start {datetime.datetime.now()}")
    with psycopg2.connect(
            host=settings.AUTH_POSTGRES_HOST, port=settings.AUTH_POSTGRES_PORT,
            user=settings.AUTH_POSTGRES_USER,
            password=settings.AUTH_POSTGRES_PASSWORD, database=settings.AUTH_POSTGRES_DB
    ) as postgres_conn:
        cursor = postgres_conn.cursor(cursor_factory=DictCursor)
        cursor.execute("""SELECT table_name FROM information_schema.tables
               WHERE table_schema = 'customers'""")
        list_tables = [table[0] for table in cursor.fetchall()]

        insert_cursor = postgres_conn.cursor()
        dt = datetime.datetime.utcnow() - datetime.timedelta(days=40)
        month = dt.month
        year = dt.year
        label = "users_logs_" + str(year) + "_" + str(month)
        if label not in list_tables:
            query_create_partition_table = f"""
            create table customers.{label}
            (check(EXTRACT(YEAR FROM created_at) = {year}),
            check(EXTRACT(MONTH FROM created_at) = {month}))
            inherits(users_logs)
            """
            cursor.execute(query_create_partition_table)
            postgres_conn.commit()
            set_logs(f"Partition {label} created")
        query_count = f"""
                    SELECT count(*)
                    FROM users_logs WHERE EXTRACT(YEAR FROM created_at) = {year} AND 
                    EXTRACT(MONTH FROM created_at) = {month};
                """
        cursor.execute(query_count)
        query = f"""
            SELECT *
            FROM only users_logs WHERE EXTRACT(YEAR FROM created_at) = {year} AND 
            EXTRACT(MONTH FROM created_at) = {month};
        """
        number = 0
        cursor.execute(query)
        while main_table_data := cursor.fetchmany(STEP):

            for line in main_table_data:
                print(line)
                query_insert = f"""
                INSERT INTO {label} (id, user_id, user_agent, user_action, created_at) VALUES (
                '{line['id']}', '{line['user_id']}', '{line['user_agent']}', 
                 '{line['user_action']}', '{line['created_at']}');
                """
                insert_cursor.execute(query_insert)
                del_query = f"""
                DELETE FROM only users_logs WHERE id = '{line[0]}';
                """
                insert_cursor.execute(del_query)
            postgres_conn.commit()
            number += STEP
            set_logs(f"{number} records move to {label}")


if __name__ == "__main__":
    while True:
        partition_start()
        time.sleep(PAUSE)
