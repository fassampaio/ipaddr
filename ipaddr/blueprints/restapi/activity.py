
from flask import jsonify
from flask_restful import Resource

from ipaddr.models import Activity
from .tokens import token_required
from .clients import client_filter


class ActivityResource(Resource):
    method_decorators = {
        'get': [token_required, client_filter]
    }

    def get(self, *args, **kwargs):
        activities = Activity.query.all()
        output = []
        act_counter = 0
        if activities:
            for activity in activities:
                activity_data = {}
                activity_data['domain'] = activity.domain
                activity_data['action'] = activity.action
                activity_data['objato'] = activity.obj
                activity_data['date'] = activity.date
                activity_data['remote_ip'] = activity.owner_ip
                activity_data['user'] = activity.user_id
                output.append(activity_data)
                act_counter += 1
            
            return jsonify(
                    {
                        'total_activities': act_counter,
                        'activities': output
                    }
                )
        else:
            return jsonify({'warning': 'Activities not found.'})
