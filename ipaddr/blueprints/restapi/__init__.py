from flask import Blueprint
from flask_restful import Api

from .status import StatusResource
from .logins import UserResource
from .tokens import TokenResource
from .clients import ClientResource
from .ipaddresses import IpaddrResource, CleanupResource, DelAllResource
from .activity import ActivityResource


bp = Blueprint("restapi", __name__, url_prefix="/api/v1")
api = Api(bp)


def init_app(app):
    api.add_resource(StatusResource, "/status")
    api.add_resource(UserResource, "/users")
    api.add_resource(TokenResource, "/token")
    api.add_resource(ClientResource, "/clients")
    api.add_resource(IpaddrResource, "/ipaddresses")
    api.add_resource(CleanupResource, "/cleanup")
    api.add_resource(DelAllResource, "/delall")
    api.add_resource(ActivityResource, "/activity")

    app.register_blueprint(bp)
