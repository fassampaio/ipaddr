
import jwt
from datetime import datetime, timedelta
from functools import wraps

from flask import jsonify, request, current_app
from flask_restful import Resource
from werkzeug.security import check_password_hash

from ipaddr.models import db, Users, Activity


def token_required(f):
    """This function creates a decorator for limit access to flask routes
    Args:
        f (func): Function to requires token for access
    Returns:
        decorator: Access decorator
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Check request header for authorization token
        if 'authorization' in request.headers:
            token = request.headers['authorization']
        if not token:
            return jsonify({'error': 'Token is missing.'})
        try:
            # Verify token integrity and expiration date
            data = jwt.decode(token, key=current_app.config['SECRET_KEY'], algorithms='HS256')
            current_user = Users.query.filter_by(username=data['username']).first()
        except:
            return jsonify({'error': 'Invalid token.'})
        return f(current_user, *args, **kwargs)
    return decorated


class TokenResource(Resource):
    def get(self):
        # Get credentials from request
        auth = request.authorization
        # Get remote IP address from caller
        remote_addr = request.remote_addr
        # Verify if any field is empty
        if not auth or not auth.username or not auth.password:
            # Return operation result to caller
            return jsonify({'error': 'Invalid credentials.'})
        # Search for user in database
        user = Users.query.filter_by(username=auth.username).first()
        # If user not found
        if not user:
            # Return operation result to caller
            return jsonify({'error': 'Invalid credentials.'})
        # Check password
        if check_password_hash(user.password, auth.password):
            # Create a payload
            payload = {
                'username': auth.username,
                'exp': datetime.now() + timedelta(days=3650)
            }
            # Generates JWT (JSON Web Token)
            token = jwt.encode(payload, key=current_app.config['SECRET_KEY'], algorithm='HS256')
            now = datetime.now()
            # Create a Activity record
            new_activity = Activity(
                domain = 'token',
                action = 'generate',
                obj = 'generate token',
                date = now,
                owner_ip = remote_addr,
                user_id = auth.username
            )
            db.session.add(new_activity)
            db.session.commit()
            # Return token
            return jsonify({'token': token})

        # Return operation result to caller
        return jsonify({'error': 'Invalid credentials.'})
