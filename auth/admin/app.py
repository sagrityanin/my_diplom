from datetime import datetime
from flask import Blueprint, request
from flask_restx import Api  # type: ignore
from flask_migrate import Migrate  # type: ignore
from flask.cli import AppGroup
import click
from opentelemetry import trace  # type: ignore
from opentelemetry.sdk.trace import TracerProvider  # type: ignore
from opentelemetry.instrumentation.flask import FlaskInstrumentor  # type: ignore
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter  # type: ignore
from opentelemetry.exporter.jaeger.thrift import JaegerExporter  # type: ignore

from service.user_v1 import api as user_ns  # type: ignore
from service.price_v1 import api as price_ns
from service.subsribtion_v1 import api as subscribtion_ns
from service.token_v1 import api as token_ns
from db.postgres import init_db, db  # type: ignore
from models.users import Users  # type: ignore
from models.roles import Roles  # type: ignore
from core.application import app  # type: ignore
from core import schemas, hash  # type: ignore
from core.config import settings  # type: ignore

# The line need for write in users tables. I don't naw why
from models.ext_auth import ExtAuth


def configure_tracer() -> None:
    trace.set_tracer_provider(TracerProvider())
    trace.get_tracer_provider().add_span_processor(
        BatchSpanProcessor(
            JaegerExporter(
                agent_host_name='jaeger',
                agent_port=6831,
            )
        )
    )
    trace.get_tracer_provider().add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))


if settings.TRACER_ON:
    configure_tracer()

    FlaskInstrumentor().instrument_app(app)

    @app.before_request
    def before_request():
        request_id = request.headers.get('X-Request-Id')
        if not request_id:
            raise RuntimeError('request id is required')

blueprint = Blueprint('api', __name__, url_prefix='/admin/api/v1')

api = Api(blueprint,
          title="My API",
          description="My Cool API")
api.add_namespace(user_ns)
api.add_namespace(price_ns)
api.add_namespace(subscribtion_ns)
api.add_namespace(token_ns)

app.register_blueprint(blueprint)

authorizations = schemas.authorizations

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
init_db(app)
migrate = Migrate(app, db)

superuser_cli = AppGroup('superuser')


@superuser_cli.command('create')
def create_superuser():
    login = click.prompt('Please enter your login')
    email = click.prompt('Please enter your email')
    password = click.prompt('Please enter your password')
    time_created = str(datetime.now())
    superuser_role = Roles.query.filter_by(role='superuser').first()
    hash_password = hash.get_hash(password, time_created)
    try:
        new_user = Users(
            login=login,
            email=email,
            password=hash_password,
            role_id=superuser_role.id,
            created_at=time_created,
            is_active=True
        )
        db.session.add(new_user)
        db.session.commit()
        click.echo(f"Superuser with login {login} and email {email} created")
    except Exception:
        click.echo(f"Superuser with login {login} and email {email} NOT created")


@superuser_cli.command('delete')
def delete_superuser():
    superuser_role = Roles.query.filter_by(role='superuser').first()
    while click.confirm('Do you want to delete superuser?'):
        if click.confirm('Do you want to use you login?'):
            login = click.prompt('Please enter your login')
            superuser = Users.query.filter_by(login=login, role_id=superuser_role.id).first()
            if superuser:
                db.session.delete(superuser)
                db.session.commit()
                click.echo(f"Superuser with login {login} and email {superuser.email} was deleted")
            else:
                click.echo(f"Superuser with login {login} NOT found")
        elif click.confirm('Do you want to use you email?'):
            email = click.prompt('Please enter your email')
            superuser = Users.query.filter_by(email=email, role_id=superuser_role.id).first()
            if superuser:
                db.session.delete(superuser)
                db.session.commit()
                click.echo(f"Superuser with login {superuser.login} and email {email} was deleted")
            else:
                click.echo(f"Superuser with login {email} NOT found")
        else:
            click.confirm('Do you want to exit?', abort=True)


app.cli.add_command(superuser_cli)
