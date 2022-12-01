import click
from ipaddr.ext.database import db
from werkzeug.security import generate_password_hash
from ipaddr.models import Users, Ipaddresses, Clients, Activity

def create_db():
    """Create a database file."""
    db.create_all()


def drop_db():
    """Cleanup a database."""
    db.drop_all()


def init_app(app):
    # add multiple commands in a bulk
    for command in [create_db, drop_db]:
        app.cli.add_command(app.cli.command()(command))

    # add a single command
    @app.cli.command()
    @click.option('--name', '-n')
    @click.option('--username', '-u')
    @click.option('--password', '-p')
    def add_user(name, username, password):
        """Adds a new user to the database"""
        hashed_password = generate_password_hash(password, method='pbkdf2:sha512')
        new_user = Users(
            name = name,
            username = username,
            password = hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        return Users.query.all()

    # add a single command
    @app.cli.command()
    @click.option('--name', '-n')
    @click.option('--ipaddress', '-i')
    def add_client(name, ipaddress):
        # Creates a client record
        new_ip = Clients(
            ipaddress=ipaddress,
            description=name,
            owner_ip = '127.0.0.1',
            user_id = 1
        )
        db.session.add(new_ip)
        db.session.commit()
        return Clients.query.all()
