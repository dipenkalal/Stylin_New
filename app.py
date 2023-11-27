import atexit
import datetime
from decouple import config
import pymongo
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import os
from werkzeug.utils import secure_filename
import json
from pymongo.errors import BulkWriteError
from marshmallow import Schema, fields, validate, ValidationError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
from apscheduler.schedulers.background import BackgroundScheduler

# MongoDB connection string goes here.
uri = config('MONGO_URI')
myclient = pymongo.MongoClient(uri)
mydb = myclient['Stylin8']
mycol = mydb['User']
clothes_collection = mydb['Clothes'] 

#OpenWeather API
OPENWEATHER_API_KEY = config('OPENWEATHER_API_KEY')


#initializing the app
app = Flask(__name__)
app.secret_key = config('SECRET_KEY')
cors = CORS(app)
app.config["CORS_HEADERS"] = "content-type"

# Configure the maximum file size to 5MB
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png', '.jpeg']
app.config['UPLOAD_PATH'] = 'uploads'

#mail configuration for forgot_password
app.config["MAIL_SERVER"] = config('MAIL_SERVER')
app.config["MAIL_PORT"] = int(config('MAIL_PORT'))  # Note: Converted to int
app.config["MAIL_USERNAME"] = config('MAIL_USERNAME')
app.config["MAIL_PASSWORD"] = config('MAIL_PASSWORD')
app.config["MAIL_USE_TLS"] = False
app.config["MAIL_USE_SSL"] = True

mail = Mail(app)

#registration schema 
class RegisterSchema(Schema):
    fname = fields.Str(required=True, validate=validate.Length(min=1))
    lname = fields.Str(required=True, validate=validate.Length(min=1))
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=6))

#Login Schema
class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=6))

# # Initialize the limiter
# limiter = Limiter(
#     app,
#     key_func=get_remote_address,
#     default_limits=["200 per day", "50 per hour"]
# )



#image_upload
def allowed_file(filename):
    return '.' in filename and \
           os.path.splitext(filename)[1].lower() in app.config['UPLOAD_EXTENSIONS']

@app.route('/upload_clothe', methods=['POST'])
def upload_clothe():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    # Get the tags and other details from the User
    category = request.form.get('category')
    clothe_type = request.form.get('type')
    color = request.form.get('color')
    brand = request.form.get('brand')
    occasion = request.form.get('occasion')
    if not category:
        return jsonify({'error': 'No category provided'}), 400
    if file.filename == '':
        return jsonify({'error': 'No file selected for uploading'}), 400
    if not allowed_file(file.filename):
        return jsonify({'error': 'Allowed file types are .jpg, .png, .jpeg'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['   UPLOAD_PATH'], filename)
        file.save(file_path)

        # Insert file path, category, and tags into the MongoDB database
        clothes_document = {
            'file_path': file_path,
            'category': category,
            'type': clothe_type,
            'color': color,
            'brand': brand,
            'occasion': occasion,
            'user_id': request.form.get('user_id')  # Assuming the user_id is passed in the form
        }
        result = clothes_collection.insert_one(clothes_document)

        return jsonify({'message': 'File successfully uploaded', 'file_path': file_path}), 201
    else:
        return jsonify({'error': 'Allowed file types are .jpg, .png, .jpeg'}), 400

# database logic to handle uploaded file information
def add_clothe_to_db(user_id, file_path, category):
    clothe_data = {
        'user_id': user_id,
        'file_path': file_path,
        'category': category
    }
    # 'clothe_pictures' is your collection for storing clothes information
    mydb['clothe_pictures'].insert_one(clothe_data)


#Register_Page API
@app.route("/Register", methods=["POST"])
# @limiter.limit("5 per minute")
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

#Login_Page API
@app.route("/Login", methods=["POST"])
# @limiter.limit("10 per minute")
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



#Logout API    
@app.route('/Logout', methods=['POST'])
def logout():
    # Clear user session
    session.clear()
    return jsonify({'message': 'Logout successful'})


#Profile_Setup API
@app.route("/ProfileSetup", methods=["POST"])
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


#Google_Login API
@app.route('/Login/google', methods=['POST'])
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
    

# Facebook login route
@app.route('/Login/facebook', methods=['POST'])
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


def generate_appsecret_proof(app_secret, access_token):
    import hmac
    import hashlib
    key = app_secret.encode('utf-8')
    msg = access_token.encode('utf-8')
    return hmac.new(key, msg, hashlib.sha256).hexdigest()

#Forgot_Password route
@app.route("/forgot_password", methods=["POST"])
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

def generate_reset_token(email, expiration=1800):
    s = URLSafeTimedSerializer(app.secret_key)
    return s.dumps(email, salt='password-reset-salt')

def verify_reset_token(token, expiration=1800):
    s = URLSafeTimedSerializer(app.secret_key)
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=expiration)
    except:
        return None
    return email


@app.route('/import_clothes_data', methods=['POST'])
def import_clothes_data():
    file_path = 'clothes_data.json'  # Replace with your actual JSON file path
    with open(file_path, 'r') as file:
        data = json.load(file)
        try:
            # Insert data into the MongoDB collection
            result = clothes_collection.insert_many(data)
            return jsonify({'message': f'{result.inserted_ids} records inserted successfully!'}), 201
        except BulkWriteError as bwe:
            # Return detailed error message if a BulkWriteError occurs
            return jsonify({'error': str(bwe.details)}), 500


@app.route('/import_user_data', methods=['POST'])
def import_user_data():
    file_path = 'expanded_users_data.json'  # Replace with your actual JSON file path
    with open(file_path, 'r') as file:
        data = json.load(file)
        try:
            # Attempt to insert data into the MongoDB collection
            result = mycol.insert_many(data, ordered=False)
            return jsonify({'message': f'{len(result.inserted_ids)} records inserted successfully!'}), 201
        except BulkWriteError as bwe:
            # Return detailed error message if a BulkWriteError occurs
            return jsonify({'error': str(bwe.details)}), 500



@app.route('/get_weather', methods=['GET'])
def get_weather():
    # Get the city name from the request
    city = request.args.get('city', 'New York')  # Default to New York if no city is provided

    # OpenWeatherMap API endpoint with city
    url = f'http://api.openweathermap.org/data/2.5/weather?q={city}&appid={OPENWEATHER_API_KEY}&units=metric'

    try:
        response = requests.get(url)
        response.raise_for_status()  # Will raise an HTTPError if the HTTP request returned an unsuccessful status code

        data = response.json()

        # Create a document to save in the database
        weather_document = {
            'city': city,
            'temperature': data['main']['temp'],
            'weather_conditions': data['weather'][0]['description'],
            'last_updated': datetime.datetime.utcnow()  # Store the current time
        }

        # Save or update the document in the database
        mydb['weather_data'].update_one({'city': city}, {'$set': weather_document}, upsert=True)

        return jsonify({'temperature': temperature, 'weather_conditions': weather_conditions}), 200
    
    except requests.exceptions.HTTPError as errh:
        return jsonify({'error': f'HTTP Error: {errh}'}), errh.response.status_code
    except requests.exceptions.ConnectionError as errc:
        return jsonify({'error': f'Error Connecting: {errc}'}), 500
    except requests.exceptions.Timeout as errt:
        return jsonify({'error': f'Timeout Error: {errt}'}), 500
    except requests.exceptions.RequestException as err:
        return jsonify({'error': f'Error: {err}'}), 500
    

# Define the function to update weather data
def update_weather_data():
    # List of cities to update
    cities = ["Windsor", "London", "Cambridge"]  # Add your list of cities here

    for city in cities:
        weather_data = get_weather,
        if weather_data:
            mydb['weather_data'].update_one({'city': city}, {'$set': weather_data}, upsert=True)

# Initialize the scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=update_weather_data, trigger="interval", hours=1)
scheduler.start()

# Ensure that the scheduler is shut down when exiting the app
atexit.register(lambda: scheduler.shutdown())


@app.route('/add_favorite', methods=['POST'])
def add_favorite():
    user_id = request.json.get('user_id')
    clothe_id = request.json.get('clothe_id')
    # Add more fields if necessary

    # Insert into favorites collection
    mydb['favorites'].insert_one({'user_id': user_id, 'clothe_id': clothe_id})
    return jsonify({'message': 'Added to favorites'}), 200

@app.route('/get_favorites', methods=['GET'])
def get_favorites():
    user_id = request.args.get('user_id')

    favorites = mydb['favorites'].find({'user_id': user_id})
    favorite_items = [item for item in favorites]

    return jsonify(favorite_items), 200



def recommend_clothes(user_id):
    # Example logic: find the most favorited category of clothes for this user
    favorite_category = mydb['favorites'].aggregate([
        {'$match': {'user_id': user_id}},
        {'$group': {'_id': '$category', 'count': {'$sum': 1}}},
        {'$sort': {'count': -1}},
        {'$limit': 1}
    ])

    if favorite_category:
        category = favorite_category[0]['_id']
        recommended_items = mydb['clothes'].find({'category': category}).limit(10)
        return [item for item in recommended_items]
    else:
        return []



@app.errorhandler(Exception)
def handle_exception(e):
    # logging the exception here for debugging purposes
    print(f"An error occurred: {str(e)}")
    return jsonify({'error': 'A server error occurred'}), 500


if __name__ == "__main__":
    app.run(port=5000)