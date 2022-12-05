from flask import Blueprint

from .views import login, logout, ipaddress, ipaddressdel, clients, clientdel, users, userdel

bp = Blueprint("webui", __name__, template_folder="templates")

bp.add_url_rule("/", view_func=login, methods=['GET', 'POST'])
bp.add_url_rule("/logout", view_func=logout, methods=['GET'])

bp.add_url_rule("/ipaddress", view_func=ipaddress, methods=['GET', 'POST'])
bp.add_url_rule("/ipaddressdel", view_func=ipaddressdel, methods=['POST'])
bp.add_url_rule("/clients", view_func=clients, methods=['GET', 'POST'])
bp.add_url_rule("/clientdel", view_func=clientdel, methods=['POST'])
bp.add_url_rule("/users", view_func=users, methods=['GET', 'POST'])
bp.add_url_rule("/userdel", view_func=userdel, methods=['POST'])


def init_app(app):
    app.register_blueprint(bp)
