import logging

logging.basicConfig(filename='cron.log', filemode='w', format='%(message)s', level=logging.INFO)


def set_logs(message: str) -> None:
    logging.info(message)
