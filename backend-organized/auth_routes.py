from flask import Blueprint, app, request, jsonify, session
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from database import mycol  # Update with the correct import path
from schemas import RegisterSchema, LoginSchema  # Update with the correct import path
from utils import generate_appsecret_proof, generate_reset_token  # Update with the correct import path
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Message
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import os

# Create a Blueprint for auth routes
auth_bp = Blueprint('auth', __name__)

limiter = Limiter(key_func=get_remote_address)

@auth_bp.route("/Register", methods=["POST"])
@limiter.limit("5 per minute")
def register():
    try:
        content = RegisterSchema().load(request.get_json())
    except ValidationError as err:
        return jsonify(err.messages), 400

# Check if user already exists
    existing_user = mycol.find_one({"email": content["email"]})
    if existing_user:
        return jsonify({"error": "User with this email already exists"}), 409

#Hashing the password before saving
    hashed_password = generate_password_hash(content["password"], method='pbkdf2:sha256')
    content["password"] = hashed_password

#upon successful registration
    mycol.insert_one(content)
    return jsonify({"message": "User registered successfully!"}), 201




@auth_bp.route("/Login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    try:
        # Validate the input data using the LoginSchema
        content = LoginSchema().load(request.get_json())
    except ValidationError as err:
        # Return validation errors
        return jsonify(err.messages), 400

    try:
        user = mycol.find_one({"email": content["email"]})

        if not user:
            return jsonify({"error": "Email not found"}), 401

        if not check_password_hash(user["password"], content["password"]):
            return jsonify({"error": "Wrong password"}), 401

        # If email and password are verified, you can add additional logic here
        # ...

        return jsonify({"message": "Login successful!"}), 200

    except pymongo.errors.OperationFailure as e:
        return jsonify({"error": "Database operation failed"}), 500
    except Exception as e:
        return jsonify({"error": "An error occurred"}), 500
    



@auth_bp.route('/Logout', methods=['POST'])
def logout():
    # Clear user session
    session.clear()
    return jsonify({'message': 'Logout successful'})




@auth_bp.route("/ProfileSetup", methods=["POST"])
def profile_setup():
    content = request.get_json()
    session['email'] = content["email"]
    
    required_fields = ["first_name", "last_name", "dob", "gender", "phone"]
    if not all(key in content for key in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    mycol.update_one({"email": content["email"]}, {"$set": {
        "first_name": content["first_name"],
        "last_name": content["last_name"],
        "dob": content["dob"],
        "gender": content["gender"],
        "phone": content["phone"]
    }})
    return jsonify({"message": "Profile set up successfully!"}), 200




@auth_bp.route('/Login/google', methods=['POST'])
def login_with_google():
    token = request.json['id_token']
    client_id = config('GOOGLE_CLIENT_ID')
    try:
        # Verify the Google ID token
        id_info = id_token.verify_oauth2_token(token, google_requests.Request(), client_id)
        if id_info['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Invalid token')

        # Check if user is already registered
        email = id_info['email']
        user = mycol.find_one({'email': email})
        if not user:
            # Create a new user document
            user = {
                'email': email,
                'password': None  # No password for Google login
            }

            # Insert the user document into the users collection
            mycol.insert_one(user)

        # Update user's session
        session['user'] = user
        return jsonify({'message': 'Login with Google successful'})
    
    except ValueError:
        return jsonify({'message': 'Invalid ID token'})
    



@auth_bp.route('/Login/facebook', methods=['POST'])
def login_with_facebook():
    access_token = request.json['access_token']
    app_id = config('FACEBOOK_APP_ID')  # replaced with config
    app_secret = config('FACEBOOK_APP_SECRET')  # replaced with config
    try:
        # Verify the Facebook access token
        params = {
            'access_token': access_token,
            'appsecret_proof': generate_appsecret_proof(app_secret, access_token)
        }
        response = request.get(f'https://graph.facebook.com/v13.0/debug_token?input_token={access_token}', params=params)
        data = response.json()

        if 'error' in data or not data['data']['is_valid']:
            raise ValueError('Invalid access token')

        # Check if user is already registered
        user_id = data['data']['user_id']
        user = mycol.find_one({'facebook_id': user_id})
        if not user:
            # User is not registered, perform registration logic here

            # Create a new user document
            user = {
                'facebook_id': user_id,
                'password': None  # No password for Facebook login

            }

            # Insert the user document into the users collection
            mycol.insert_one(user)

        # Update user's session
        session['user'] = user

        return jsonify({'message': 'Login with Facebook successful'})
    except ValueError:
        return jsonify({'message': 'Invalid access token'})
    




@auth_bp.route("/forgot_password", methods=["POST"])
def forgot_password():
    email = request.json['email']
    user = mycol.find_one({'email': email})
    if not user:
        return jsonify({'message': 'Email not found'}), 404

    token = generate_reset_token(email)
    
    #Send an email with the token using SendGrid
    message = Mail(
        from_email='171080107009.acet@gmail.com',
        to_emails=email,
        subject='Password Reset Request',
        html_content=f'''
        To reset your password, visit the following link:
        http://127.0.0.1:5000/forgot_password?token={token}

        If you did not make this request, then simply ignore this email and no changes will be made.
        ''')
    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        response = sg.send(message)
    except Exception as e:
        print(e)
        return jsonify({"error": "An error occurred while sending the email"}), 500

    return jsonify({'message': 'Password reset email sent!'})
    email = request.json['email']
    user = mycol.find_one({'email': email})
    if not user:
        return jsonify({'message': 'Email not found'}), 404

    token = generate_reset_token(email)
    
    #Send an email with the token
    msg = Message('Password Reset Request', sender='171080107009.acet@gmail.com', recipients=[email])
    msg.body = f'''
    To reset your password, visit the following link:
    YOUR_FLUTTER_APP_RESET_LINK?token={token}

    If you did not make this request, then simply ignore this email and no changes will be made.
    '''
    mail.send(msg)

    return jsonify({'message': 'Password reset email sent!'})


