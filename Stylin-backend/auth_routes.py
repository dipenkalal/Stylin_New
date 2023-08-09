from flask import Flask,Blueprint, request, jsonify, session, current_app
from itsdangerous import URLSafeTimedSerializer, BadSignature
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
import requests
from google.auth.transport import requests
from google.oauth2 import id_token
from flask_mail import Mail, Message

auth_routes = Blueprint('auth_routes', __name__)
app = Flask(__name__)

# MongoDB connection settings
uri = 'mongodb://localhost:27017'  
client = MongoClient(uri)
db = client['Authentication']
users_collection = db['User']

app.secret_key = '123456789'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'patelnency1210'
app.config['MAIL_PASSWORD'] = 'zfyfkqkradzpcpza'
app.config['MAIL_DEFAULT_SENDER'] = 'patelnency1210@gmail.com'

mail = Mail(app)
@auth_routes.route('/register', methods=['POST'])
def register_user():
    full_name = request.form['full_name']
    email = request.form['email']
    password = request.form['password']

    # Check if the user already exists in the database
    if users_collection.find_one({'email': email}):
        return jsonify({'message': 'User already exists'})

    # Generate password hash
    hashed_password = generate_password_hash(password)

    # Store the user in the database with full name, email, and hashed password
    users_collection.insert_one({
        'full_name': full_name,
        'email': email,
        'password': hashed_password,
        'location': None,
        'height': None,
        'weight': None,
        'size': None,
        'gender': None,
        'birthday': None,
        'phone_number': None
    })
    return jsonify({'message': 'Registration successful'})

@auth_routes.route('/user/<email>', methods=['GET', 'PATCH'])
def get_or_update_user(email):
    # Get the user from the database by email
    user = users_collection.find_one({'email': email})

    if not user:
        return jsonify({'message': 'User not found'})

    if request.method == 'PATCH':
        # Update user properties based on provided data
        data = request.get_json()

        # Allow updating any of the properties
        allowed_properties = ['full_name', 'location', 'height', 'weight', 'size', 'gender', 'birthday', 'phone_number', 'password']

        for prop in allowed_properties:
            if prop in data:
                if prop == 'password':
                    # If updating password, generate new password hash
                    user[prop] = generate_password_hash(data[prop])
                else:
                    user[prop] = data[prop]

        # Update the user in the database
        users_collection.update_one({'email': email}, {'$set': user})

    return jsonify(user)

@auth_routes.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    # Check if the user exists in the database
    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'message': 'User not found'})

    # Check if the password matches
    if not check_password_hash(user['password'], password):
        return jsonify({'message': 'Invalid password'})

    # Set user session
    session['email'] = email

    return jsonify({'message': 'Login successful'})

@auth_routes.route('/logout', methods=['POST'])
def logout():
    # Clear user session
    session.clear()

    return jsonify({'message': 'Logout successful'})

# API endpoint for login with Google
@auth_routes.route('/login/google', methods=['POST'])
def login_with_google():
    token = request.json['id_token']
    client_id = '68440261549-nqmtdbbibluvequom2kpqn4miaq62b15.apps.googleusercontent.com'
    try:
        # Verify the Google ID token
        id_info = id_token.verify_oauth2_token(token, requests.Request(), client_id)
        if id_info['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Invalid token')

        # Check if user is already registered
        email = id_info['email']
        user = users_collection.find_one({'email': email})
        if not user:

            # Create a new user document
            user = {
                'email': email,
                'password': None  # No password for Google login
            }

            # Insert the user document into the users collection
            users_collection.insert_one(user)

        # Update user's session
        session['user'] = user

        return jsonify({'message': 'Login with Google successful'})
    except ValueError:
        return jsonify({'message': 'Invalid ID token'})

# API endpoint for login with Facebook
@auth_routes.route('/login/facebook', methods=['POST'])
def login_with_facebook():
    access_token = request.json['access_token']
    app_id = '3523379587978072'
    app_secret = 'f3f533a9f4b935930368d9bbe8e2a87b'
    try:
        # Verify the Facebook access token
        params = {
            'access_token': access_token,
            'appsecret_proof': generate_appsecret_proof(app_secret, access_token)
        }
        response = requests.get(f'https://graph.facebook.com/v13.0/debug_token?input_token={access_token}', params=params)
        data = response.json()

        if 'error' in data or not data['data']['is_valid']:
            raise ValueError('Invalid access token')

        # Check if user is already registered
        user_id = data['data']['user_id']
        user = users_collection.find_one({'facebook_id': user_id})
        if not user:
            # User is not registered, perform registration logic here

            # Create a new user document
            user = {
                'facebook_id': user_id
            }

            # Insert the user document into the users collection
            users_collection.insert_one(user)

        # Update user's session
        session['user'] = user

        return jsonify({'message': 'Login with Facebook successful'})
    except ValueError:
        return jsonify({'message': 'Invalid access token'})

def generate_appsecret_proof(app_secret, access_token):
    import hmac
    import hashlib
    key = app_secret.encode('utf-8')
    msg = access_token.encode('utf-8')
    return hmac.new(key, msg, hashlib.sha256).hexdigest()
@auth_routes.route('/forgot_password', methods=['POST'])
def forgot_password():
    email = request.form['email']

    # Check if the user exists in the database
    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'message': 'User not found'})
    reset_link = generate_reset_link(email)

    # Store the reset link in the user's document in the database
    users_collection.update_one({'email': email}, {'$set': {'reset_link': reset_link}})

    # Generate reset token
    serializer = URLSafeTimedSerializer(current_app.secret_key)
    reset_token = serializer.dumps(email, salt='reset-salt')

    send_email(email, reset_link)
    return jsonify({'message': 'Reset link sent to the user\'s email'})

def generate_reset_link(email):
    # Generate a unique reset token
    token = 'your_reset_token'  # Replace with your actual token

    # Create a serializer with a secret key
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

    # Generate the reset link URL with the token
    reset_link = serializer.dumps(email, salt='reset-salt')  # No need to set max_age here

    # Replace 'localhost:8000' with your actual domain and route
    reset_link = f'http://localhost:8000/reset_password/{reset_link}'

    return reset_link

def send_email(to_email, reset_link):
    msg = Message('Password Reset', recipients=[to_email])
    msg.body = f"Click the following link to reset your password: {reset_link}"
    mail.send(msg)
def verify_reset_token(reset_token):
    serializer = URLSafeTimedSerializer(current_app.secret_key)
    try:
        email = serializer.loads(reset_token, salt='reset-salt', max_age=3600)
        # Add additional validation logic if needed
        # For example, check if the user exists in the database
        return email
    except BadSignature:
        return None
    
@auth_routes.route('/reset_password', methods=['POST'])
def reset_password():
    reset_token = request.form['reset_token']
    new_password = request.form['new_password']

    # Verify reset token
    email = verify_reset_token(reset_token)
    if not email:
        return jsonify({'message': 'Invalid reset token'})

    # Update the user's password in the database
    hashed_password = generate_password_hash(new_password)
    users_collection.update_one({'email': email}, {'$set': {'password': hashed_password}})

    return jsonify({'message': 'Password reset successful'})

