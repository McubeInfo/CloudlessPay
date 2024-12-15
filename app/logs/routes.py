from flask import jsonify
from models import APILog, User
from datetime import datetime, timedelta
from . import logs_bp
from utils.utils import *


@logs_bp.route('/logs', methods=['GET'])
@login_required
def get_logs():
    cutoff_time = datetime.utcnow() - timedelta(hours=1)
    current_user = session.get('user')
    email = current_user.get('email')
    user = User.get_user_by_email(email)
    recent_logs = APILog.query.filter(
        # APILog.log_time >= cutoff_time,
        APILog.user_id == user.id  # Assuming 'user' field stores the email
    ).order_by(APILog.log_time.desc()).all()
    
    log_data = [{
        "id": log.id,
        "time": log.log_time.strftime('%Y-%m-%d %H:%M:%S'),
        "endpoint": log.endpoint,
        "user": User.query.filter(User.id == log.user_id).first().username,
        "domain": log.domain,
        "platform": log.platform,
        "response": log.response
    } for log in recent_logs]
    
    return jsonify(log_data)
