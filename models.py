from app.config import db
from uuid import uuid4
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from datetime import datetime, timedelta
load_dotenv()
import os
import razorpay
import logging
from flask import jsonify
import requests

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

RAZORPAY_KEY_ID = os.environ.get('RAZORPAY_KEY_ID')
RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET')
client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4()))
    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True, index=True)
    password = db.Column(db.String())
    razorpay_key_id = db.Column(db.String(), nullable=True)
    razorpay_key_secret = db.Column(db.String(), nullable=True)
    access_token = db.Column(db.String(), nullable=True)
    jti = db.Column(db.String(), nullable=True)
    payment_token = db.Column(db.String(), nullable=True)
    razorpay_customer_id = db.Column(db.String(), nullable=True)
    billing_address = db.Column(db.JSON, nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.now())
    updated_at = db.Column(db.DateTime, onupdate=datetime.now())    
   
    credits = db.relationship('UserCredits', back_populates='user', lazy=True, cascade="all, delete-orphan")
    billing = db.relationship('Billing', back_populates='user', lazy=True, cascade="all, delete-orphan")
    api_logs = db.relationship('APILog', back_populates='user', lazy=True, cascade="all, delete-orphan")
    usage_logs = db.relationship('UsageLog', back_populates='user', lazy=True, cascade="all, delete-orphan")
    
    is_deleted = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    # Password handling
    def set_hashed_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    @classmethod
    def get_user_by_email(cls, email):
        return cls.query.filter_by(email = email).first()
    
    def save(self):
        db.session.add(self)
        db.session.commit()
        
    def delete(self):
        self.is_deleted = True
        db.session.commit()
        
    def set_razorpay_credentials(self, key_id, key_secret):
        if not os.environ.get('SECRET_KEY'):
            raise ValueError("SECRET_KEY is not set in the environment variables.")
        self.razorpay_key_id = key_id
        cipher_suite = Fernet(str(os.environ.get('SECRET_KEY')).encode())
        self.razorpay_key_secret = cipher_suite.encrypt(key_secret.encode()).decode()

    def get_razorpay_key_secret(self):
        if not self.razorpay_key_secret:
            return None
        cipher_suite = Fernet(str(os.environ.get('SECRET_KEY')).encode())
        return cipher_suite.decrypt(self.razorpay_key_secret.encode()).decode()
    
    def set_billing_address(self, address_data):
        self.billing_address = address_data
        self.save()

    def get_billing_address(self):
        return self.billing_address or {}
    
    
    def charge_for_usage(self):
        user_credits = UserCredits.query.filter_by(user_id=self.id).first()
        if user_credits:
            if user_credits.credits_exhausted_date:
                days_since_exhaustion = (datetime.now() - user_credits.credits_exhausted_date).days
                if days_since_exhaustion >= 30:
                    usage_logs = UsageLog.query.filter_by(user_id=self.id).all()
                    amount_due = len(usage_logs)  # or use your own calculation
                    if self.payment_token:
                        self.process_payment(amount_due)
                    else:
                        logger.error(f"No payment token found for user {self.id}")
                else:
                    logger.info(f"User {self.id} has not reached 30 days since credits exhausted.")
            else:
                logger.info(f"User {self.id} has not exhausted their credits yet.")
        else:
            logger.error(f"UserCredits not found for user {self.id}")
            
    
    def process_payment(self, amount_due):
        """Process payment using Razorpay."""
        try:
            token_id = self.payment_token
            if not token_id:
                return jsonify({"message": "No saved cards found."}), 400
            
            if not self.razorpay_customer_id:
                return jsonify({"error": "Customer not found"}), 400
            
            # Create an order for automated payment
            order = client.order.create({
                'amount': amount_due * 100,
                'currency': 'INR',
            })
            
            print(order)
            
            url = f"https://api.razorpay.com/v1/payments" 
            headers = {
                "content-type": "application/json"
            }
            billing_details = self.get_billing_address()
            payload = {
                "amount": amount_due * 100,  # amount in paise
                "currency": "INR",
                "order_id": order['id'],
                "email": billing_details['email'],
                'contact': billing_details['phone'],
                'method': 'card',
                'token': token_id,
                'card': {},
                'customer_id': self.razorpay_customer_id,
            }
            
            response = requests.post(url, auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET), headers=headers, json=payload)
            response_data = response.json()
            if response.status_code == 200:
                if 'id' in response_data:
                    return jsonify({
                        "message": "Payment charged successfully.",
                        "payment_id": response_data['id']
                    }), 200
                else:
                    print("Missing 'id' in response:", response_data)
                    return jsonify({"error": "Unexpected response structure from Razorpay"}), 500
            else:
                print("Error from Razorpay API:", response_data)
                return jsonify({"error": response_data.get('error', 'An error occurred')}), response.status_code
        except razorpay.errors.RazorpayError as e:
            return jsonify({"error": f"Payment failed for user {self.id}: {str(e)}"})
        finally:
            db.session.commit()

    
class RevokedToken(db.Model):
    __tablename__ = 'revoked_tokens'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120), nullable=False, unique=True)
    revoked_at = db.Column(db.DateTime, nullable=False, default=datetime.now())
    def __repr__(self):
        return f"<RevokedToken {self.jti}>" 
    
    def save(self):
        db.session.add(self)
        db.session.commit()

class APILog(db.Model):
    __tablename__ = 'api_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(), db.ForeignKey('users.id'), nullable=False)
    log_time = db.Column(db.DateTime, default=datetime.now())
    endpoint = db.Column(db.String(120))
    domain = db.Column(db.String(120))
    platform = db.Column(db.String(50))
    response = db.Column(db.Text)
    status = db.Column(db.String(20), default="success")
    
    user = db.relationship('User', back_populates='api_logs')

    def save(self):
        db.session.add(self)
        db.session.commit()
        
    def __repr__(self):
        return f'<APILog {self.endpoint}, {self.status}>'
        
class UserCredits(db.Model):
    __tablename__ = 'user_credits'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(), db.ForeignKey('users.id'), nullable=False)
    credits = db.Column(db.Integer, default=200)
    last_updated = db.Column(db.DateTime, default=datetime.now)
    credits_exhausted_date = db.Column(db.DateTime, nullable=True)

    user = db.relationship('User', back_populates='credits')
    
    @classmethod
    def get_credits_info(cls, user_id):
        return cls.query.filter_by(user_id=user_id).first()

    def consume_credit(self):
        """Deduct 1 credit per API call. Restrict access if credits are exhausted."""
        if self.credits > 0:
            self.credits -= 1
            self.last_updated = datetime.now()
            db.session.commit()
            return True
        else:
            if not self.credits_exhausted_date:
                self.credits_exhausted_date = datetime.now()  # Set the exhaustion date when credits hit zero
                db.session.commit()
            return False
        
    def save(self):
        db.session.add(self)
        db.session.commit()

class UsageLog(db.Model):
    __tablename__ = 'usage_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(), db.ForeignKey('users.id'), nullable=False)
    log_time = db.Column(db.DateTime, default=datetime.now())
    endpoint = db.Column(db.String(120))
    platform = db.Column(db.String(50))
    amount_billed = db.Column(db.Float, default=0.0)  # 1 rupee if billed
    credits_used = db.Column(db.Integer, default=0)
    
    user = db.relationship('User', back_populates='usage_logs')
    
    def save(self):
        db.session.add(self)
        db.session.commit()
        
    @staticmethod
    def get_monthly_usage(user_id, month, year):
        """Fetch total usage for the specified month and year."""
        start_date = datetime(year, month, 1)
        end_date = start_date + timedelta(days=31)
        usage = db.session.query(
            db.func.sum(UsageLog.credits_used).label('total_credits')
        ).filter(
            UsageLog.user_id == user_id,
            UsageLog.log_time >= start_date,
            UsageLog.log_time < end_date
        ).first()
        return usage.total_credits or 0
    
    @classmethod
    def get_monthly_usage_and_amount(cls, user_id, month, year):
        credits_used = db.session.query(db.func.sum(cls.credits_used)).filter(
            cls.user_id == user_id,
            db.extract('month', cls.log_time) == month,
            db.extract('year', cls.log_time) == year
        ).scalar() or 0

        amount_billed = db.session.query(db.func.sum(cls.amount_billed)).filter(
            cls.user_id == user_id,
            db.extract('month', cls.log_time) == month,
            db.extract('year', cls.log_time) == year
        ).scalar() or 0

        return credits_used, amount_billed
    
class Billing(db.Model):
    __tablename__ = 'billing'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(), db.ForeignKey('users.id'), nullable=False)
    amount_due = db.Column(db.Float, default=0.0)
    billing_date = db.Column(db.DateTime, default=datetime.now())
    payment_status = db.Column(db.String(20), default='pending')  # e.g., pending, successful, failed
    last_payment_attempt = db.Column(db.DateTime, nullable=True)

    user = db.relationship('User', back_populates='billing')

    def calculate_amount_due(self):
        usage_credits = UsageLog.get_monthly_usage(
            self.user_id,
            self.billing_date.month,
            self.billing_date.year
        )
        self.amount_due = usage_credits
        db.session.commit()
            
    def save(self):
        db.session.add(self)
        db.session.commit()