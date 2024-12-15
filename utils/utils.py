from flask import jsonify, session
from flask_jwt_extended import verify_jwt_in_request, get_jwt
from functools import wraps
from requests.auth import HTTPBasicAuth
import requests
from models import RevokedToken, APILog
from app import db
from flask import request
import json
from models import User

def token_required(fn):
    @wraps(fn)
    def decorated_function(*args, **kwargs):
        verify_jwt_in_request()
        jti = get_jwt().get("jti")

        if is_token_revoked(jti):
            return jsonify({"error": "Token has been revoked"}), 401

        return fn(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'User not logged in'}), 401
        return f(*args, **kwargs)
    return decorated_function


def is_token_revoked(jti):
    token = RevokedToken.query.filter_by(jti=jti).first()
    return token is not None

def add_token_to_blacklist(jti):
    revoked_token = RevokedToken(jti=jti)
    db.session.add(revoked_token)
    db.session.commit()

def validate_razorpay_credentials(key_id, key_secret):
    url = "https://api.razorpay.com/v1/payments"
    response = requests.get(url, auth=HTTPBasicAuth(key_id, key_secret))
    
    return response.status_code == 200

def identify_client(user_agent):
    """Identify the client based on the User-Agent string."""
    if 'Postman' in user_agent:
        return 'Postman'
    elif 'curl' in user_agent:
        return 'cURL'
    elif 'Chrome' in user_agent:
        return 'Google Chrome'
    elif 'Firefox' in user_agent:
        return 'Mozilla Firefox'
    elif 'Safari' in user_agent and 'Chrome' not in user_agent:
        return 'Apple Safari'
    elif 'Edge' in user_agent:
        return 'Microsoft Edge'
    else:
        return 'Unknown Client'

def log_api_request(endpoint, email, response_data, status):
    """Helper function to log API request."""
    domain = request.headers.get('Origin', 'unknown domain')
    user_agent = request.headers.get('User-Agent', 'Unknown')
    platform_info = identify_client(user_agent)
    
    user = User.get_user_by_email(email=email)

    log_entry = APILog(
        endpoint=endpoint,
        user_id=user.id,
        domain=domain,
        platform=platform_info,
        response=json.dumps(response_data) if isinstance(response_data, dict) else str(response_data),
        status=status
    )
    db.session.add(log_entry)
    db.session.commit()