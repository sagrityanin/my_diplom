FROM python:3.9

RUN apt-get update 
RUN apt install -y libpq-dev netcat
RUN mkdir -p /home/flask
WORKDIR /home/flask
COPY . /home/flask

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

EXPOSE 5000

COPY ./requirements.txt /
RUN python -m pip install --upgrade pip
RUN pip install -r /requirements.txt

COPY . .

CMD chmod +x /home/flask/enterypiont.sh


ENTRYPOINT ["/home/flask/entrypoint.sh"]
