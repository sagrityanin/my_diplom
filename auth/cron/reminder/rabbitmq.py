from datetime import datetime
import logging
import json
import pika
from pymongo import MongoClient
from typing import Optional
import uuid
import repackage

repackage.up()
from config import settings  # type: ignore


class Queue:
    def __init__(self):
        self.mongo_client = MongoClient(settings.MONGO_DSN)
        self.mongo_db = self.mongo_client[settings.MONGO_DB]
        self.mongo_notification = self.mongo_db.get_collection(settings.MONGO_NOTIFICATION_COLLECTION)
        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters(host='rabbitmq'))
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue=settings.NOTIFICATION_QUEUE, durable=True)

    def __exit__(self):
        self.connection.close()

    def make_message(
        self,
        notification_id: str,
        user_email: str,
        message: str,
        subject: Optional[str],
    ) -> str:
        message_uuid = str(uuid.uuid4())
        insert_dict = {
            "message_id": message_uuid,
            "email": user_email,
            "notification_id": notification_id,
            "status": "generated",
            "created": str(datetime.now()),
            "subject": subject,
            "message": message
        }
        self.mongo_notification.insert_one(insert_dict)
        # now _id of non-json-serializable type is insert_dict, probably,
        # ? because of Motor in-place update? so, let's remove it
        if '_id' in insert_dict:
            del insert_dict['_id']
        if self.put_email_message(insert_dict):
            return f"send email {insert_dict['email']}"
        else:
            return f"Can not send email {insert_dict['email']}"

    def put_email_message(self, insert_dict: dict) -> bool:
        insert_message = json.dumps(insert_dict)
        try:
            self.channel.basic_publish(
                exchange='',
                routing_key='email.notification',
                body=insert_message,
            )
            return True
        except Exception:
            logging.info(f"rabbitmq error {insert_dict}")
            return False


queue = Queue()
