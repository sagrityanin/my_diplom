FROM python:3.9

RUN apt-get update 
RUN apt install -y libpq-dev netcat
RUN mkdir -p /home/flask
WORKDIR /home/flask

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

EXPOSE 5000

COPY ./requirements.txt /
RUN python -m pip install --upgrade pip
RUN pip install -r /requirements.txt

COPY . .
COPY ./filebeat-6.2.4-amd64.deb .
RUN dpkg -i filebeat-6.2.4-amd64.deb
COPY ./filebeat.yml /etc/filebeat/
RUN chmod go-w /etc/filebeat/filebeat.yml
CMD chmod +x /home/flask/entrypoint.sh


ENTRYPOINT ["bash", "/home/flask/entrypoint.sh"]
