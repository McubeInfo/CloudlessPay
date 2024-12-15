from . import main_bp
from flask import render_template, redirect, url_for, session, request, jsonify
from models import User
import requests

@main_bp.app_context_processor
def inject_user():
    # Check if user is in session
    user = session.get('user')
    
    if user is None:
        keys = {}
        access_token = False
    else:
        # Get user object from database
        user = User.get_user_by_email(user['email'])
        
        # Ensure user exists in database before accessing attributes
        if user:
            keys = {
                'key_id': user.razorpay_key_id if user.razorpay_key_id else None,
                'key_secret': User.get_razorpay_key_secret(user) if user.razorpay_key_secret else None
            }
            access_token = True if user.access_token else False
        else:
            keys = {}
            access_token = False

    return {
        'is_logged_in': user is not None,
        'current_user': user if user else {},
        'authentication_keys': keys if keys.get('key_id') else {},
        'is_access_token': access_token,
    }


@main_bp.get('/')
def home_redirect():
    return redirect(url_for('main_bp.home'))

@main_bp.get('/docs/')
def home():
    return render_template('home.html')

@main_bp.get('/docs/app')
def app():
    return render_template('index.html')

@main_bp.get('/docs/razorpay')
def doc_page():
    return render_template('razorpay.html')

@main_bp.get('/docs/settings')
def settings():
    return render_template('settings.html')

def newsletterSubscriber(email, stream_name):
    url = "https://www.zohoapis.in/creator/custom/contact_mcubeinfotech/addLeadIntoEmailCampaign"
    
    params = {
        "publickey": "nrmEdjYaOO6fvTfQrhXx07k4O"
    }

    payload = {
        "email": email,
        "streamName": stream_name
    }

    try:
        response = requests.post(url, params=params, json=payload)
        
        if response.status_code == 200:
            print("Data pushed successfully:", response.json())
            return response.json()
        else:
            print(f"Failed to push data. Status Code: {response.status_code}, Response: {response.text}")
            return {"error": response.text}

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return {"error": str(e)}


@main_bp.route('/docs/subscribe-to-cloudlesspay', methods=['POST'])
def subscriberEmail():
    try:
        data = request.json
        email = data.get('email')
        stream_name = data.get('streamName')
        
        if not email or not stream_name:
            return jsonify({"error": "Missing 'email' or 'streamName' in the payload."}), 400
        
        # Call the function to push data to Zoho
        result = newsletterSubscriber(email, stream_name)
        
        if "error" in result:
            return jsonify(result), 400
        
        return jsonify({
            "message": "Data pushed to Zoho successfully!",
            "response": result
        }), 200
    
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    

def customerInquiry(formData):
    url = "https://www.zohoapis.in/creator/custom/contact_mcubeinfotech/Create_Ticket"
    params = {
        "publickey": "RD2BWP5v4fVRvpfqZjdXWgb9x"
    }

    try:
        response = requests.post(url, params=params, json=formData)
        if response.status_code == 200:
            print("Data pushed successfully:", response.json())
            return {"status": "success", "data": response.json()}
        else:
            print(f"Failed to push data. Status Code: {response.status_code}")
            return {"status": "error", "message": response.text}

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return {"status": "error", "message": str(e)}

@main_bp.route('/docs/contact', methods=['POST'])
def contactForm():
    try:
        data = request.form
        result = customerInquiry(dict(data))

        if result["status"] == "error":
            return jsonify(result), 400

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"status": "error", "message": f"Unexpected error: {str(e)}"}), 500
