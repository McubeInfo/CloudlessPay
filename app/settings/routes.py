from flask import request, jsonify, session, render_template
from . import settings_bp
from models import User, UserCredits, UsageLog
from utils.utils import *
from datetime import datetime, timedelta
import razorpay
import os
from dotenv import load_dotenv
load_dotenv()
from dateutil.relativedelta import relativedelta

RAZORPAY_KEY_ID = os.environ.get('RAZORPAY_KEY_ID')
RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET')

razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))


@settings_bp.post('/save-payment-method')
@login_required
def save_payment_method():
    current_user = session.get('user')
    user_name = current_user['email']
    user = User.get_user_by_email(user_name)
    try:
        if not user.razorpay_customer_id:
            return jsonify({"error": "Please save your Billing Address first, then try again."}), 400
        
        data = request.get_json()
        
        if not all(attr in data['card_details'] for attr in ['number', 'expiry_month', 'expiry_year', 'cvv']):
            return jsonify({"error": "Invalid card details provided."}), 400
        
        token = razorpay_client.token.create({
            "customer_id": user.razorpay_customer_id,
            "method": "card",
            "card": {
                "number": data["card_details"]["number"],
                "expiry_month": data["card_details"]["expiry_month"],
                "expiry_year": data["card_details"]["expiry_year"],
                "cvv": data["card_details"]["cvv"]
            }
        })
                
        user.payment_token = token['id']
        user.save()            

        return jsonify({
            "message": "Payment method saved successfully.",
            "token_id": token['id']
        }), 200

    except razorpay.errors.SignatureVerificationError:
        return jsonify({"message": "Payment signature verification failed."}), 400
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"error": f"An unexpected error occurred {e}."}), 500

@settings_bp.get('/get-cards')
@login_required
def get_saved_cards():
    current_user = session.get('user')
    user_name = current_user['email']
    user = User.get_user_by_email(user_name)

    try:
        token_id = user.payment_token
        if not token_id:
            return jsonify({"message": "No saved cards found."}), 404
        
        url = "https://api.razorpay.com/v1/tokens/fetch"
        headers = {
            "content-type": "application/json"
        }

        payload = {
            "id": token_id
        }

        response = requests.post(url, auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET), headers=headers, json=payload)
        token_details = response.json()
        
        if 'card' in token_details:
            card = token_details['card']
            saved_card = {
                'issuer': card.get('issuer', 'Unknown'),
                'last4': card.get('last4', '****'),
                'network': card.get('network', 'Unknown'),
                'type': card.get('type', 'Unknown'),
                'international': card.get('international', False),
                'emi': card.get('emi', False),
                'id': token_id
            }

            return jsonify({"cards": [saved_card]}), 200

        return jsonify({"message": "No card information found."}), 404

    except Exception as e:
        print(f"Error fetching saved cards: {str(e)}")
        return jsonify({"error": f"An unexpected error occurred while fetching saved cards. {e}"}), 500


@settings_bp.post('/remove-card')
@login_required
def remove_saved_card():
    current_user = session.get('user')
    user_name = current_user['email']
    user = User.get_user_by_email(user_name)

    try:
        data = request.json
        
        token_id = user.payment_token
        
        if not token_id or token_id != data.get('token_id'):
            return jsonify({"message": "Card not found or already removed."}), 404
        
        url = "https://api.razorpay.com/v1/tokens/delete"
        headers = {
            "content-type": "application/json"
        }

        payload = {
            "id": token_id
        }

        response = requests.delete(url, auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET), headers=headers, json=payload)
        
        user.payment_token = None
        user.save()

        return jsonify({"message": "Card removed successfully."}), 200

    except Exception as e:
        print(f"Error removing card: {str(e)}")
        return jsonify({"error": f"An error occurred while removing the card {e}."}), 500


@settings_bp.post('/charge-with-token')
@login_required
def charge_with_token():
    current_user = session.get('user')
    user_name = current_user['email']
    user = User.get_user_by_email(user_name)

    try:
        token_id = user.payment_token
        if not token_id:
            return jsonify({"message": "No saved cards found."}), 404
        
        if not user.payment_token:
            return jsonify({"error": "Customer not found"}), 404
        
        # Create an order for automated payment
        order = razorpay_client.order.create({
            'amount': 100,
            'currency': 'INR',
        })
        
        print(order)
        
        url = f"https://api.razorpay.com/v1/payments" 
        headers = {
            "content-type": "application/json"
        }
        billing_details = user.get_billing_address()
        payload = {
            "amount": 100,  # amount in paise
            "currency": "INR",
            "order_id": order['id'],
            "email": billing_details['email'],
            'contact': billing_details['phone'],
            'method': 'card',
            'token': token_id,
            'card': {
                'cvv': '922'
            },
            'customer_id': user.razorpay_customer_id,
        }
        print(payload)
        
        response = requests.post(url, auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET), headers=headers, json=payload)
        
        print("Razorpay response:", response.status_code, response.text)
        
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

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"error": f"An error occurred during the transaction. {e}"}), 500


@settings_bp.post('/save_billing_address')
@login_required
def save_billing_address():
    current_user = session.get('user')
    
    user_name = current_user['email']
    user = User.get_user_by_email(user_name)

    data = request.get_json()
    
    user.set_billing_address({
        'company_name': data['company_name'],
        'phone': data['phone'],
        'email': data['email'],
        'address': data['address'],
        'country': data['country'],
        'state': data['state'],
        'city': data['city'],
        'pincode': data['pincode'],
        'gst_registered': data['gst_registered'],
        'gst_number': data['gst_number'],
    })
    
    if not user.razorpay_customer_id:
        customer = razorpay_client.customer.create({
            'name': data['company_name'],
            'email': data['email'],
            'contact': data['phone']
        })
        user.razorpay_customer_id = customer['id']
    
    user.save()
    
    return jsonify({"message": "Billing address saved successfully."}), 200

@settings_bp.get('/get_billing_address')
@login_required
def get_bill_address():
    current_user = session.get('user')
    
    user_name = current_user['email']
    user = User.get_user_by_email(user_name)
    
    return jsonify({"message": "Billing addresses retrieved successfully.", "billings": user.get_billing_address()}), 200

    
# ----------------------------------------------------------------
# Credits routes
# ----------------------------------------------------------------
  
@settings_bp.get('/get_credits')
@login_required
def get_user_credits():
    current_user = session.get('user')
    user = User.get_user_by_email(current_user['email'])

    credits_used, amount_billed = UsageLog.get_monthly_usage_and_amount(user_id=user.id, month=datetime.now().month, year=datetime.now().year)
    return jsonify({
        'credits': credits_used,
        'amount_billed': amount_billed
    }), 200

@settings_bp.get('/get_monthwise_credits')
@login_required
def get_users_monthwise_credits():
    current_user = session.get('user')
    user = User.get_user_by_email(current_user['email'])
    
    today = datetime.today()
    month = request.args.get('month', 'this-month')

    
    if month == 'this-month':
        start_date = today.replace(day=1)
        end_date = (start_date + relativedelta(months=1)).replace(day=1)
    elif month == 'last-month':
        start_date = (today.replace(day=1) - relativedelta(months=1)).replace(day=1)
        end_date = start_date + relativedelta(months=1)
    elif month == 'last-previous-month':
        start_date = (today.replace(day=1) - relativedelta(months=2)).replace(day=1)
        end_date = start_date + relativedelta(months=1)
    else:
        return jsonify({'error': 'Invalid month selection'}), 400

    
    user_id = user.id  

    # Fetch monthly usage and amount billed (modifying the logic here)
    total_credits, total_amount = UsageLog.get_monthly_usage_and_amount(user_id, start_date.month, start_date.year)
    
    return jsonify({
        'credits': total_credits,
        'amount_billed': total_amount,
    })