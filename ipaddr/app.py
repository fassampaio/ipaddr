
import os
from flask import Flask
from ipaddr.ext import configuration


def minimal_app(**config):
    app = Flask(
        __name__,
        static_url_path='',
        static_folder='blueprints/webui/static',
        template_folder='blueprints/webui/templates'
    )
    configuration.init_app(app, **config)
    return app


def create_app(**config):
    app = minimal_app(**config)
    configuration.load_extensions(app)
    return app
