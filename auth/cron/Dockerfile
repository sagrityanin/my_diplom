FROM python:3.9

RUN apt-get update 
RUN apt install -y libpq-dev
RUN mkdir -p /app
WORKDIR /app
COPY . /app

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

EXPOSE 50051

COPY ./requirements.txt /
RUN python -m pip install --upgrade pip
RUN pip install -r /requirements.txt

#COPY . .

#CMD  ["python3", "get_payload.py"]
