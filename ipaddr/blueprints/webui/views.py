
from datetime import timedelta
from urllib.parse import urlparse, urljoin

from flask import render_template, request, flash, redirect, url_for, current_app, abort
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.security import check_password_hash

from ipaddr.models import Users, Clients, Ipaddresses


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = Users.query.filter_by(username=username).first()
        if not user:
            flash('Username does not exist.', category='error')
        else:
            if check_password_hash(user.password, password):
                login_user(user, remember=True, duration=timedelta(minutes=15))
                flash('Logged in successfully!', category='success')
                next = request.args.get('next')
                if not is_safe_url(next):
                    return abort(400)
                return redirect(next or url_for('webui.ipaddress'))
            else:
                flash('Incorrect password, try again.', category='error')

    return render_template('login.html', user=current_user, ver=current_app.config['VERSION'])


@login_required
def logout():
    logout_user()
    return redirect(url_for('webui.login'))


@login_required
def ipaddress():
    ip_addresses = Ipaddresses.query.all()
    return render_template('ipaddresses.html', ipaddresses=ip_addresses, user=current_user, ver=current_app.config['VERSION'])


@login_required
def clients():
    clients = Clients.query.all()
    return render_template('clients.html', clients=clients, user=current_user, ver=current_app.config['VERSION'])


@login_required
def users():
    users = Users.query.all()
    return render_template('users.html', users=users, user=current_user, ver=current_app.config['VERSION'])
