
import time
from datetime import datetime
from flask import jsonify, current_app
from flask_restful import Resource

from ipaddr.models import db

class StatusResource(Resource):
    def get(self):
        # Get actual date and time
        format_data = "%Y-%m-%d %H:%M:%S"
        now = datetime.now().replace(microsecond=0)
        # Convert date and time to unix timestamp
        unix_time = int(str(time.mktime(now.timetuple())).split('.')[0])
        date_str = now.strftime(format_data)

        # Return responce json data
        return jsonify({
            'ipaddr': {
                'version': current_app.config['VERSION'],
                'timestamp': unix_time,
                'datetime': date_str
            }
        })
