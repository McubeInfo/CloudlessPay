from flask import request, jsonify, session, render_template, redirect, url_for
from . import auth_bp
from models import User, UserCredits
from flask_jwt_extended import create_access_token
from marshmallow import ValidationError
import uuid
from utils.utils import *
import smtplib
import random
import string
from email.mime.text import MIMEText

# A dictionary to store OTPs temporarily
otp_store = {}

def generate_otp(length=6):
    """Generate a random OTP."""
    return ''.join(random.choices(string.digits, k=length))

def send_email(receiver_email, subject, body):
    """Send an email using SMTP."""
    sender_email = "contact@mcubeinfotech.com"
    sender_password = "faxb zfvt bdhn hiah"
    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = receiver_email

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
    except Exception as e:
        raise Exception(f"Failed to send email: {str(e)}")
    
@auth_bp.post('/send-otp')
def send_otp():
    """Generate and send OTP to user's email."""
    try:
        data = request.get_json()
        email = data.get('email')
        if not email:
            return jsonify({"error": "Email is required"}), 400

        user = User.get_user_by_email(email=email)
        if user:
            return jsonify({"error": "User already registered"}), 403

        # Generate OTP
        otp = generate_otp()
        otp_store[email] = otp

        # Send OTP via email
        subject = "Your OTP for Registration on CloudlessPay"
        body = f"Your OTP for CloudlessPay Platform is: {otp}"
        send_email(email, subject, body)

        return jsonify({"message": "OTP sent to email"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@auth_bp.post('/verify-otp')
def verify_otp():
    """Verify OTP and register user."""
    try:
        data = request.get_json()
        email = data.get('email')
        otp = data.get('otp')

        if not email or not otp:
            return jsonify({"error": "Email and OTP are required"}), 400

        # Validate OTP
        if email not in otp_store or otp_store[email] != otp:
            return jsonify({"error": "Invalid OTP"}), 403

        # Register the user
        new_user = User(
            username=data.get('username'),
            email=email
        )
        new_user.set_hashed_password(password=data.get('password'))
        new_user.save()
        
        user_credits = UserCredits(user_id=new_user.id)
        
        db.session.add(user_credits)
        db.session.commit()

        # Clean up OTP store
        del otp_store[email]

        return jsonify({"message": "User successfully registered"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@auth_bp.get('/authorize')
def loginPage():
    if 'user' not in session:
        return render_template('login.html')
    else:
        return render_template('index.html')

@auth_bp.post('/register')
def register():
    try:
        data = request.get_json()
        user = User.get_user_by_email(email=data.get('email'))

        if user:
            return jsonify({"error": "User already registered"}), 403

        new_user = User(
            username=data.get('username'),
            email=data.get('email')
        )
        new_user.set_hashed_password(password=data.get('password'))
        new_user.save()
        
        user_credits = UserCredits(user_id=new_user.id)
        
        db.session.add(user_credits)
        db.session.commit()
        
        return jsonify({'message': 'User Successfully Created'}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@auth_bp.post('/login')
def login():
    try:
        data = request.get_json()

        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Missing email or password'}), 400

        user = User.get_user_by_email(email=data.get('email'))

        if not user:
            return jsonify({'error': 'Invalid email or password'}), 401

        if not user.check_password(password=data.get('password')):
            return jsonify({'error': 'Invalid username or password'}), 401
        
        session['user'] = {
            'id': user.id,
            'email': user.email,
            'name': user.username
        }


        return jsonify({'message': 'Login Successfully', 'redirect': '/docs/app'}), 200

    except ValidationError as ve:
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@auth_bp.route('/set-credentials', methods=['POST', 'OPTIONS'])
@login_required
def set_razorpay_credentials():
    if request.method == 'OPTIONS':
        return '', 200
    current_user = session.get('user')
    
    if not current_user:
        return jsonify({'error': 'User not logged in'}), 401
    
    user = User.get_user_by_email(current_user['email'])
    
    data = request.get_json()
    
    razorpay_key_id = data.get('key_id')
    razorpay_key_secret = data.get('key_secret')
    
    if not validate_razorpay_credentials(razorpay_key_id, razorpay_key_secret):
        return jsonify({"error": "Invalid Razorpay credentials"}), 401

    if not razorpay_key_id or not razorpay_key_secret:
        return jsonify({"error": "Both key_id and key_secret are required"}), 400

    user.set_razorpay_credentials(razorpay_key_id, razorpay_key_secret)
    user.save()
    
    return jsonify({'message': 'Razorpay credentials saved successfully'}), 200

@auth_bp.get('/create-access-token')
@login_required
def generate_access_token():
    current_user = session.get('user')
    
    if not current_user:
        return jsonify({'error': 'User not logged in'}), 401
    
    user = User.get_user_by_email(current_user['email'])
    
    if not user.razorpay_key_id or not user.razorpay_key_secret:
        return jsonify({'error': 'Razorpay credentials must be set before generating an access token'}), 400
    
    if not validate_razorpay_credentials(user.razorpay_key_id, user.get_razorpay_key_secret()):
        return jsonify({"error": "Invalid Razorpay credentials"}), 401
    
    if user.access_token:
        return jsonify({'error': 'Access token already exists. Delete it before creating a new one.'}), 403

    jti = str(uuid.uuid4())
    access_token = create_access_token(identity=current_user, expires_delta=False, additional_claims={"jti": jti})
    user.access_token = access_token
    user.jti = jti
    user.save()
    
    return jsonify({'message': 'New Access Token Generated', 'access_token': access_token}), 200


@auth_bp.delete('/delete-access-token')
@login_required
def delete_access_token():
    
    current_user = session.get('user')
    
    if not current_user:
        return jsonify({'error': 'User not logged in'}), 401
    user = User.get_user_by_email(current_user['email'])

    if user.access_token:
        add_token_to_blacklist(user.jti)
        user.access_token = None
        user.jti = None
        user.save()
        
        return jsonify({"message": "Access token deleted successfully"}), 200

    return jsonify({"error": "No access token found"}), 400

@auth_bp.get('/get-access-token')
@login_required
def get_access_token():
    try:
        user = session.get('user')
        user = User.get_user_by_email(user['email'])
        access_token = user.access_token
        if not access_token:
            return jsonify({"error": "Access token not found, Please generate the access token and try again."}), 400
        return jsonify({'access_token': access_token}), 200
    except Exception as e:
        return jsonify({'error': e})

@auth_bp.get('/logout')
def logout():
    session.pop('user', None)
    return render_template('home.html')