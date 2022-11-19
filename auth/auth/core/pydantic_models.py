from pydantic import BaseModel


class PayLog(BaseModel):
    id: str
    subscription_id: str
    event_time: str
    provider: str
    status: str


class PayLogList(BaseModel):
    pay_log_list: list[PayLog]
