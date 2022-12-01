from datetime import datetime

from flask import jsonify, request
from flask_restful import Resource
from werkzeug.security import generate_password_hash

from ipaddr.models import db, Users, Activity
from .tokens import token_required
from .clients import client_filter


class UserResource(Resource):
    method_decorators = {
        'get': [token_required, client_filter],
        'post': [token_required, client_filter],
        'delete': [token_required, client_filter]
    }

    def get(self, *args, **kwargs):
        users = Users.query.all()
        output = []
        if users:
            # Loop for IP addresses
            for user in users:
                user_data = {}
                # Populates the key with values
                user_data['id'] = user.id
                user_data['name'] = user.name
                user_data['username'] = user.username
                user_data['password'] = user.password
                user_data['created'] = user.created
                # Add item do dict
                output.append(user_data)

            # Return response with all IP addresses found
            return jsonify({'users': output})

        else:
            return jsonify(
                {'error': 'Users not found.'}
            )


    def post(self, current_user, *args, **kwargs):
        data = request.get_json()
        # Get remote IP address from caller
        remote_addr = request.remote_addr
        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha512')
        user = Users.query.filter_by(username=data['username']).first()
        if user:
            return jsonify({'error': 'Username already exists.'})
        elif len(data['username']) < 2:
            return jsonify({'error': 'Username must be greater than 1 characters.'})
        elif len(data['password']) < 7:
            return jsonify({'error': 'Password must be greater than 6 characters.'})
        elif len(data['name']) < 2:
            return jsonify({'error': 'Name must be greater than 1 characters.'})
        else:
            now = datetime.now()
            new_user = Users(
                username=data['username'],
                password=hashed_password,
                name=data['name'],
                created = now
            )
            # Create a Activity record
            new_activity = Activity(
                domain = 'user',
                action = 'add',
                obj = data['username'],
                date = now,
                owner_ip = remote_addr,
                user_id = current_user.username
            )
            db.session.add(new_user)
            db.session.add(new_activity)
            db.session.commit()
            return jsonify({'message': 'New user created.'})


    def delete(self, current_user, *args, **kwargs):
        # Get JSON POST body data from request
        data = request.get_json()
        # Get remote IP address from caller
        remote_addr = request.remote_addr
        # Search for user in database
        user = Users.query.filter_by(username=data['username']).first()
        # If user not found
        if not user:
            return jsonify({'error': 'User not found.'})
        # if user found
        else:
            now = datetime.now()
            # Create a Activity record
            new_activity = Activity(
                domain = 'user',
                action = 'delete',
                obj = data['username'],
                date = now,
                owner_ip = remote_addr,
                user_id = current_user.username
            )
            # Delete user from database
            db.session.delete(user)
            db.session.add(new_activity)
            db.session.commit()
            # Return operation result to caller
            return jsonify({'message': 'User has been deleted.'})
