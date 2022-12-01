
from datetime import datetime
from functools import wraps

from flask import jsonify, request
from flask_restful import Resource

from ipaddr.utils import is_valid_ip_address
from ipaddr.models import db, Ipaddresses, Clients, Activity
from .tokens import token_required


def client_filter(f):
    """This function creates a decorator to limit what IP remote IPs can call API
    Args:
        f (func): Function to requires token for access

    Returns:
        decorator: Access decorator
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Gets remoto IP
        remote_ip = request.remote_addr

        # Search IP in database
        ipaddress = Clients.query.filter_by(ipaddress=remote_ip).first()
        if ipaddress:
            return f(*args, **kwargs)
        else:
            return jsonify({'error': f'IP {remote_ip} not in client list.'})
    return decorated


class ClientResource(Resource):
    method_decorators = {
        'get': [token_required, client_filter],
        'post': [token_required, client_filter],
        'delete': [token_required, client_filter]
    }

    def get(self, current_user, *args, **kwargs):
        # Get all clients in database
        clients = Clients.query.all()
        output = []
        # Loop for clients
        for client in clients:
            ipaddr_data = {}
            # Populates the key with values
            ipaddr_data['ipaddress'] = client.ipaddress
            ipaddr_data['description'] = client.description
            ipaddr_data['owner_ip'] = client.owner_ip
            ipaddr_data['created'] = client.created
            ipaddr_data['owner'] = client.user_id
            # Add item do dict
            output.append(ipaddr_data)

        # Return response with all IP addresses found
        return jsonify({'clients': output})


    def post(self, current_user, *args, **kwargs):
        # Get JSON POST body data from request
        data = request.get_json()
        remote_addr = request.remote_addr
        # Search for clients IPs in database
        ip_address = Clients.query.filter_by(ipaddress=data['ipaddress']).first()
        # Client found
        if ip_address:
            return jsonify({'error': 'Client IP address already exists.'})
        # Validate data
        elif not is_valid_ip_address(data['ipaddress']):
            return jsonify({'error': 'Invalid Client IP address.'})
        else:
            now = datetime.now()
            # Creates a client record
            new_ip = Clients(
                ipaddress=data['ipaddress'],
                description=data['description'],
                created = now,
                owner_ip = remote_addr,
                user_id = current_user.username
            )
            # Create a Activity record
            new_activity = Activity(
                domain = 'client',
                action = 'add',
                obj = data['ipaddress'],
                date = now,
                owner_ip = remote_addr,
                user_id = current_user.username
            )
            # Save record to database
            db.session.add(new_ip)
            db.session.add(new_activity)
            db.session.commit()
            
        # Return operation result to caller
        return jsonify({'message': 'Client IP address successfully added.'})


    def delete(self, current_user, *args, **kwargs):
        # Get JSON POST body data from request
        data = request.get_json()
        remote_addr = request.remote_addr
        # Search for client IP in database
        ip_address = Clients.query.filter_by(ipaddress=data['ipaddress']).first()
        # Verify if IP address is valid
        if not is_valid_ip_address(data['ipaddress']):
            return jsonify({'error': 'Invalid Client IP address.'})
        elif not ip_address:
            return jsonify({"error": "Client IP address don't exists."})
        else:
            now = datetime.now()
            # Create a Activity record
            new_activity = Activity(
                domain = 'client',
                action = 'delete',
                obj = data['ipaddress'],
                date = now,
                owner_ip = remote_addr,
                user_id = current_user.username
            )
            # Delete client from database
            db.session.delete(ip_address)
            db.session.add(new_activity)
            db.session.commit()

            # Return operation result to caller
            return jsonify({'message': 'Client IP address has been deleted.'})
