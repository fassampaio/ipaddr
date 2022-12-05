
from datetime import datetime, timedelta
import jwt
from urllib.parse import urlparse, urljoin

from flask import render_template, request, flash, redirect, url_for, current_app, abort
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash

from ipaddr.models import db, Users, Clients, Ipaddresses
from ipaddr.utils import is_valid_ip_address


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
    if request.method == 'POST':
        ipaddress = request.form.get('ipaddress')
        hours = int(request.form.get('hours'))
        location = request.form.get('location').lower()
        seconds = hours * 3600
        remote_addr = request.remote_addr
        ip_address = Ipaddresses.query.filter_by(ipaddress=ipaddress, location=location).first()
        if ip_address:
            flash('IP address already exists.', category='error')
        elif not is_valid_ip_address(ipaddress):
            flash('Invalid IP address.', category='error')
        elif hours < 0:
            flash('Hours must be greater than 0.', category='error')
        elif len(location) < 2:
            flash('Location must have more than 1 character.', category='error')
        else:
            created = datetime.now()
            remove = datetime.now() + timedelta(seconds=seconds)
            new_ip = Ipaddresses(
                ipaddress=ipaddress,
                location=location.lower(),
                created = created,
                remove=remove,
                owner_ip = remote_addr,
                user_id = current_user.username
            )
            db.session.add(new_ip)
            db.session.commit()
            flash('IP Address added!', category='success')

    ip_addresses = Ipaddresses.query.all()
    return render_template('ipaddresses.html', ipaddresses=ip_addresses, user=current_user, ver=current_app.config['VERSION'])


@login_required
def ipaddressdel():
    ip_id = request.form.get('ip_id')
    ipaddress = Ipaddresses.query.filter_by(ip_id=ip_id).first()
    if ipaddress:
        db.session.delete(ipaddress)
        db.session.commit()
        flash('IP Address deleted!', category='success')
    return redirect(url_for('webui.ipaddress'))


@login_required
def clients():
    if request.method == 'POST':
        ipaddress = request.form.get('ipaddress')
        description = request.form.get('description')
        remote_addr = request.remote_addr
        client = Clients.query.filter_by(ipaddress=ipaddress).first()
        if client:
            flash('Client already exists.', category='error')
        elif not is_valid_ip_address(ipaddress):
            flash('Client invalid IP address.', category='error')
        elif len(description) < 2:
            flash('Description must be greater than 1.', category='error')
        else:
            new_client = Clients(
                ipaddress=ipaddress,
                description=description,
                owner_ip = remote_addr,
                user_id = current_user.username
            )
            db.session.add(new_client)
            db.session.commit()
            flash('Client IP Address added!', category='success')

    clients = Clients.query.all()
    return render_template('clients.html', clients=clients, user=current_user, ver=current_app.config['VERSION'])


@login_required
def clientdel():
    client_id = request.form.get('client_id')
    client = Clients.query.filter_by(client_id=client_id).first()
    if client:
        db.session.delete(client)
        db.session.commit()
        flash('Client IP deleted!', category='success')
    return redirect(url_for('webui.clients'))


@login_required
def users():
    if request.method == 'POST':
        username = request.form.get('username')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        if password1 != password2:
            flash('Passwords not match.', category='error')
        else:
            hashed_password = generate_password_hash(password1, method='sha256')
            name = request.form.get('name')
            remote_addr = request.remote_addr
            user = Users.query.filter_by(username=username).first()
            if user:
                flash('User already exists.', category='error')
            elif len(username) < 2:
                flash('Username must be greater than 1.', category='error')
            elif len(password1) < 7:
                flash('Password must be greater than 6.', category='error')
            elif len(name) < 2:
                flash('Name must be greater than 1.', category='error')
            else:
                new_user = Users(
                    username=username,
                    password=hashed_password,
                    name=name
                )
                db.session.add(new_user)
                db.session.commit()
                payload = {
                    'username': username,
                    'exp': datetime.now() + timedelta(days=3650)
                }
                token = jwt.encode(payload, key=current_app.config['SECRET_KEY'], algorithm='HS256')
                flash(f'User added. Token: {token}', category='warning')

    users = Users.query.all()
    return render_template('users.html', users=users, user=current_user, ver=current_app.config['VERSION'])


@login_required
def userdel():
    id = request.form.get('id')
    user = Users.query.filter_by(id=id).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted!', category='success')
    return redirect(url_for('webui.users'))
