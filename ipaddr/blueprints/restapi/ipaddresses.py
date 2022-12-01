
from datetime import datetime, timedelta
from flask import jsonify, request
from flask_restful import Resource

from ipaddr.utils import is_valid_ip_address
from ipaddr.models import db, Ipaddresses, Activity
from .tokens import token_required
from .clients import client_filter


class IpaddrResource(Resource):
    method_decorators = {
        'get': [token_required, client_filter],
        'post': [token_required, client_filter],
        'delete': [token_required, client_filter]
    }

    def get(self, *args, **kwargs):
        # Get all IP addresses in database
        ipaddresses = Ipaddresses.query.all()
        if ipaddresses:
            output = []
            ip_counter = 0
            # Loop for IP addresses
            for ipaddress in ipaddresses:
                ipaddr_data = {}
                # Populates the key with values
                ipaddr_data['ip_id'] = ipaddress.ip_id
                ipaddr_data['ipaddress'] = ipaddress.ipaddress
                ipaddr_data['location'] = ipaddress.location
                ipaddr_data['owner_ip'] = ipaddress.owner_ip
                ipaddr_data['created'] = ipaddress.created
                ipaddr_data['remove'] = ipaddress.remove
                ipaddr_data['owner'] = ipaddress.user_id
                # Calculate the delta time to remove IP from list
                delta = f'{ipaddress.remove - ipaddress.created}'
                ipaddr_data['delta'] = delta
                # Add item do dict
                output.append(ipaddr_data)
                ip_counter += 1

            # Return response with all IP addresses found
            return jsonify(
                {
                    'total_ip': ip_counter,
                    'ipaddresses': output
                }
            )
        else:
            return jsonify({'warning': 'IP Addresses not found.'})


    def post(self, current_user, *args, **kwargs):
        # Get JSON POST body data from request
        data = request.get_json()
        # Get remote IP address from caller
        remote_addr = request.remote_addr
        # Validated IP address format
        if is_valid_ip_address(data['ipaddress']):
            # Search for IP in database
            ip_address = Ipaddresses.query.filter_by(ipaddress=data['ipaddress'], location=data['location'].lower()).first()
            # If IP found
            if ip_address:
                return jsonify({'error': 'IP address already exists.'})
            # If IP not found
            else:
                # Define datetime values
                now = datetime.now()
                remove = datetime.now() + timedelta(seconds=data['seconds'])
                # Creates a IP record
                new_ip = Ipaddresses(
                    ipaddress = data['ipaddress'],
                    location = data['location'].lower(),
                    created = now,
                    remove = remove,
                    owner_ip = remote_addr,
                    user_id = current_user.username
                )
                # Create a Activity record
                new_activity = Activity(
                    domain = 'ip address',
                    action = 'add',
                    obj = data['ipaddress'] + ',' + data['location'].lower(),
                    date = now,
                    owner_ip = remote_addr,
                    user_id = current_user.username
                )
                # Save record to database
                db.session.add(new_ip)
                db.session.add(new_activity)
                db.session.commit()
                
                # Return operation result to caller
                return jsonify({'message': 'IP address successfully added.'})

        return jsonify({'error': 'Invalid IP address.'})


    def delete(self, current_user, *args, **kwargs):
        # Get JSON POST body data from request
        data = request.get_json()
        # Get remote IP address from caller
        remote_addr = request.remote_addr
        # Validated IP address format
        if is_valid_ip_address(data['ipaddress']):
            # Search for IP in database
            ip_address = Ipaddresses.query.filter_by(ipaddress=data['ipaddress'], location=data['location'].lower()).first()
            # If IP found
            if ip_address:
                now = datetime.now()
                # Create a Activity record
                new_activity = Activity(
                    domain = 'ip address',
                    action = 'delete',
                    obj = data['ipaddress'] + ',' + data['location'].lower(),
                    date = now,
                    owner_ip = remote_addr,
                    user_id = current_user.username
                )
                # Delete IP from database
                db.session.delete(ip_address)
                db.session.add(new_activity)
                db.session.commit()

                # Return operation result to caller
                return jsonify({'message': 'IP address has been deleted.'})
            # If IP not found
            else:
                # Return operation result to caller
                return jsonify({"error": "IP address don't exists."})
        
        # Return operation result to caller
        else:
            return jsonify({'error': 'Invalid IP address.'})


class CleanupResource(Resource):
    method_decorators = {
        'delete': [token_required, client_filter]
    }

    def delete(self, current_user, *args, **kwargs):
        # Get all IP addresses in database
        ipaddresses = Ipaddresses.query.all()
        output = []
        cleanup_counter = 0
        # Get remote IP address from caller
        remote_addr = request.remote_addr
        # Loop for IP addresses
        for ipaddress in ipaddresses:
            # Get actual date
            actual_date = datetime.now()
            location = ipaddress.location
            # Verify if date is expired
            if actual_date > ipaddress.remove:
                now = datetime.now()
                # Create a Activity record
                new_activity = Activity(
                    domain = 'ip address',
                    action = 'delete expired',
                    obj = ipaddress.ipaddress + ',' + location,
                    date = now,
                    owner_ip = remote_addr,
                    user_id = current_user.username
                )
                # Delete IP address from database
                db.session.delete(ipaddress)
                db.session.add(new_activity)
                ipaddr_data = {}
                ipaddr_data['ipaddress'] = ipaddress.ipaddress
                output.append(ipaddr_data)
                cleanup_counter += 1
                
        db.session.commit()

        # Return operation result to caller
        return jsonify(
            {
                'total_ip:': cleanup_counter,
                'ipaddresses': output
            }
        )


class DelAllResource(Resource):
    method_decorators = {
        'delete': [token_required, client_filter]
    }

    def delete(self, current_user, *args, **kwargs):
        # Get JSON POST body data from request
        data = request.get_json()
        # Get remote IP address from caller
        remote_addr = request.remote_addr
        # Get all IP addresses in database
        ipaddresses = Ipaddresses.query.all()
        output = []
        del_counter = 0
        # If IP found
        if ipaddresses:
            # Delete every IP if location is all
            if data['location'] == 'all':
                ip_deleted = db.session.query(Ipaddresses).delete()
                # Generate a response with deleted items
                for ipaddress in ipaddresses:
                    ipaddr_data = {}
                    ipaddr_data['ipaddress'] = ipaddress.ipaddress
                    ipaddr_data['location'] = ipaddress.location
                    output.append(ipaddr_data)
                    del_counter += 1
                    now = datetime.now()
                    # Create a Activity record
                    new_activity = Activity(
                        domain = 'ip address',
                        action = 'delete all',
                        obj = ipaddress.ipaddress + ',' + ipaddress.location,
                        date = now,
                        owner_ip = remote_addr,
                        user_id = current_user.username
                    )
                    db.session.add(new_activity)

            # Deleta every IP from especific location
            else:
                # Generate a response with deleted items
                for ipaddress in ipaddresses:
                    # Generate a response with deleted items
                    if data['location'] == ipaddress.location:
                        db.session.delete(ipaddress)
                        ipaddr_data = {}
                        ipaddr_data['ipaddress'] = ipaddress.ipaddress
                        ipaddr_data['location'] = ipaddress.location
                        output.append(ipaddr_data)
                        del_counter += 1
                        now = datetime.now()
                        # Create a Activity record
                        new_activity = Activity(
                            domain = 'ip address',
                            action = 'delete all',
                            obj = ipaddress.ipaddress + ',' + ipaddress.location,
                            date = now,
                            owner_ip = remote_addr,
                            user_id = current_user.username
                        )
                        db.session.add(new_activity)

            db.session.commit()

        # Return operation result to caller
        return jsonify(
            {
                'total_ip': del_counter,
                'ipaddresses': output
            }
        )
