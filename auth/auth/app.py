from flask import Blueprint, request
from flask_restx import Api  # type: ignore
from flask_migrate import Migrate  # type: ignore
from flask.cli import AppGroup

from opentelemetry import trace  # type: ignore
from opentelemetry.sdk.trace import TracerProvider  # type: ignore
from opentelemetry.instrumentation.flask import FlaskInstrumentor  # type: ignore
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter  # type: ignore
from opentelemetry.exporter.jaeger.thrift import JaegerExporter  # type: ignore

from service.token_v1 import api as token_ns  # type: ignore
from service.user_v1 import api as user_ns  # type: ignore
from service.vk_authorization_v1 import api as vk_com  # type: ignore
from service.yandex_authorization_v1 import api as yandex  # type: ignore
from db.postgres import init_db, db
from core.application import app  # type: ignore
from core import schemas  # type: ignore
from core.config import settings  # type: ignore


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

blueprint = Blueprint('api', __name__, url_prefix='/auth/api/v1')

api = Api(blueprint,
          title="My API",
          description="My Cool API")
api.add_namespace(token_ns)
api.add_namespace(user_ns)
api.add_namespace(vk_com)
api.add_namespace(yandex)
app.register_blueprint(blueprint)

authorizations = schemas.authorizations

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
init_db(app)
migrate = Migrate(app, db)

superuser_cli = AppGroup('superuser')
