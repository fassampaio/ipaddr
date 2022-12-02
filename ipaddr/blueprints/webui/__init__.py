from flask import Blueprint

from .views import login, logout, ipaddress, clients, users

bp = Blueprint("webui", __name__, template_folder="templates", static_folder="static")

bp.add_url_rule("/", view_func=login, methods=['GET', 'POST'])
bp.add_url_rule("/logout", view_func=logout, methods=['GET'])

bp.add_url_rule("/ipaddress", view_func=ipaddress)
bp.add_url_rule("/clients", view_func=clients)
bp.add_url_rule("/users", view_func=users)


def init_app(app):
    app.register_blueprint(bp)
