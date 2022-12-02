
from flask_login import LoginManager

from ipaddr.models import Users

login_manager = LoginManager()

def init_app(app):
    login_manager.init_app(app)
    login_manager.login_view = 'webui.login'

    @login_manager.user_loader
    def load_user(id):
        return Users.query.get(int(id))
