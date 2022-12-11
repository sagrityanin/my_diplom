import logging

logging.basicConfig(filename='partition.log', filemode='a', format='%(message)s', level=logging.INFO)


def set_logs(message: str) -> None:
    logging.info(message)
