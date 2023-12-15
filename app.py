import atexit
import datetime
from decouple import config
import pymongo
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, session, send_from_directory
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
<<<<<<< Updated upstream
<<<<<<< Updated upstream

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
=======
from PIL import Image
from functools import wraps
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

# MongoDB connection string goes here.
uri = config("MONGO_URI")
myclient = pymongo.MongoClient(uri)
mydb = myclient["Stylin8"]
mycol = mydb["User"]
clothes_collection = mydb["Clothes"]

# Google OAuth Configuration
GOOGLE_CLIENT_ID = config('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = config('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"


# OpenWeather API
OPENWEATHER_API_KEY = config("OPENWEATHER_API_KEY")

# initializing the app
app = Flask(__name__)
app.secret_key = config("SECRET_KEY")
>>>>>>> Stashed changes
=======
from PIL import Image
from functools import wraps
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

import jwt
import datetime
import logging



# MongoDB connection string goes here.
uri = config("MONGO_URI")
myclient = pymongo.MongoClient(uri)
mydb = myclient["Stylin8"]
mycol = mydb["User"]
clothes_collection = mydb["Clothes"]
categories = mydb["categories"]

# Google OAuth Configuration
GOOGLE_CLIENT_ID = config('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = config('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"


# OpenWeather API
OPENWEATHER_API_KEY = config("OPENWEATHER_API_KEY")

# initializing the app
app = Flask(__name__)
app.secret_key = config("SECRET_KEY")
>>>>>>> Stashed changes
cors = CORS(app)
app.config["CORS_HEADERS"] = "content-type"

# Configure the maximum file size to 5MB
<<<<<<< Updated upstream
<<<<<<< Updated upstream
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png', '.jpeg']
app.config['UPLOAD_PATH'] = 'uploads'

#mail configuration for forgot_password
app.config["MAIL_SERVER"] = config('MAIL_SERVER')
app.config["MAIL_PORT"] = int(config('MAIL_PORT'))  # Note: Converted to int
app.config["MAIL_USERNAME"] = config('MAIL_USERNAME')
app.config["MAIL_PASSWORD"] = config('MAIL_PASSWORD')
=======
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB
app.config["UPLOAD_EXTENSIONS"] = [".jpg", ".png", ".jpeg"]
app.config["UPLOAD_PATH"] = "uploads"
=======
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB
app.config["UPLOAD_EXTENSIONS"] = [".jpg", ".png", ".jpeg"]
app.config["UPLOAD_PATH"] = "D:\\StudioProjects\\Stylin-New-backend\\resources\\"
>>>>>>> Stashed changes

# mail configuration for forgot_password
app.config["MAIL_SERVER"] = config("MAIL_SERVER")
app.config["MAIL_PORT"] = int(config("MAIL_PORT"))  # Note: Converted to int
app.config["MAIL_USERNAME"] = config("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = config("MAIL_PASSWORD")
<<<<<<< Updated upstream
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes
app.config["MAIL_USE_TLS"] = False
app.config["MAIL_USE_SSL"] = True
mail = Mail(app)

<<<<<<< Updated upstream
#registration schema 
=======
>>>>>>> Stashed changes
class RegisterSchema(Schema):
    fname = fields.Str(required=True, validate=validate.Length(min=1))
    lname = fields.Str(required=True, validate=validate.Length(min=1))
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=6))
<<<<<<< Updated upstream

#Login Schema
=======
    size_preferences = fields.Str(missing=None)
    style_preferences = fields.List(fields.Str(), missing=[])

    # Add these new fields
    fname = fields.Str(missing=None)
    lname = fields.Str(missing=None)
    dob = fields.Date(missing=None)
    gender = fields.Str(missing=None)
    location = fields.Str(missing=None)
    phone = fields.Str(missing=None)
    
    

# Login Schema
>>>>>>> Stashed changes
class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=6))

<<<<<<< Updated upstream
# # Initialize the limiter
# limiter = Limiter(
#     app,
#     key_func=get_remote_address,
#     default_limits=["200 per day", "50 per hour"]
# )


<<<<<<< Updated upstream

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
=======
# registration schema
class RegisterSchema(Schema):
    fname = fields.Str(required=True, validate=validate.Length(min=1))
    lname = fields.Str(required=True, validate=validate.Length(min=1))
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=6))
    size_preferences = fields.Str(missing=None)
    style_preferences = fields.List(fields.Str(), missing=[])

# Login Schema
class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=6))

# UpdateUser Schema
class UpdateUserSchema(Schema):
    first_name = fields.Str(missing=None)
    last_name = fields.Str(missing=None)
    dob = fields.Date(missing=None)
    gender = fields.Str(missing=None)
    phone = fields.Str(missing=None)
    size_preferences = fields.Str(missing=None)
    style_preferences = fields.List(fields.Str(), missing=[])
=======
# UpdateUser Schema
class UpdateUserSchema(Schema):
    fname = fields.Str(missing=None)
    lname = fields.Str(missing=None)
    dob = fields.Date(missing=None)
    gender = fields.Str(missing=None)
    phone = fields.Str(missing=None)
    size_preferences = fields.Str(missing=None)
    style_preferences = fields.List(fields.Str(), missing=[])

# ClothesUpload Schema
class ClothesUploadSchema(Schema):
    category = fields.Str(required=True)
    type = fields.Str(required=True)
    color = fields.Str(required=True)
    brand = fields.Str(required=True)
    occasion = fields.Str(required=True)
    category_id = fields.Str(missing=None)
    sub_category = fields.Str(missing=None)
    tags = fields.List(fields.Str(), missing=[])
    user_id = fields.Str(required=True)

# Category Management
class CategorySchema(Schema):
    name = fields.Str(required=True)
    
# Category Schema
class CategorySchema(Schema):
    name = fields.Str(required=True)
    subcategories = fields.List(fields.Str(), missing=[])

    
class UpdateUserSchema(Schema):
    fname = fields.Str(missing=None)
    lname = fields.Str(missing=None)
    dob = fields.Date(missing=None)
    gender = fields.Str(missing=None)
    phone = fields.Str(missing=None)
    size_preferences = fields.Str(missing=None)
    style_preferences = fields.Str(missing=None)


def create_token(user_id):
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            app.config.get('SECRET_KEY'),
            algorithm='HS256'
        )
    except Exception as e:
        app.logger.error(f"Error creating token: {str(e)}")
        return None
    


# def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = mydb["User"].find_one({"_id": data['sub']})
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = mydb["User"].find_one({"_id": data['sub']})
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated_function


@app.route('/resources/<path:filename>')
def serve_resource(filename):
    return send_from_directory('resources', filename)


>>>>>>> Stashed changes

# image_upload
def allowed_file(filename):
    return (
        "." in filename
        and os.path.splitext(filename)[1].lower() in app.config["UPLOAD_EXTENSIONS"]
    )

<<<<<<< Updated upstream
# ClothesUpload Schema
class ClothesUploadSchema(Schema):
    category = fields.Str(required=True)
    type = fields.Str(required=True)
    color = fields.Str(required=True)
    brand = fields.Str(required=True)
    occasion = fields.Str(required=True)
    category_id = fields.Str(missing=None)
    sub_category = fields.Str(missing=None)
    tags = fields.List(fields.Str(), missing=[])
    user_id = fields.Str(required=True)

# Category Management
class CategorySchema(Schema):
    name = fields.Str(required=True)
    
# Category Schema
class CategorySchema(Schema):
    name = fields.Str(required=True)
    subcategories = fields.List(fields.Str(), missing=[])


@app.route("/upload_clothe", methods=["POST"])
def upload_clothe():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files["file"]

    # Validate form data
    try:
        data = ClothesUploadSchema().load(request.form)
    except ValidationError as err:
        return jsonify(err.messages), 400

    # Get the tags and other details from the User
    category = request.form.get("category")
    clothe_type = request.form.get("type")
    color = request.form.get("color")
    brand = request.form.get("brand")
    occasion = request.form.get("occasion")
    if not category:
        return jsonify({"error": "No category provided"}), 400
    if file.filename == "":
        return jsonify({"error": "No file selected for uploading"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "Allowed file types are .jpg, .png, .jpeg"}), 400
    if file and allowed_file(file.filename):
        
        # Image processing
        image = Image.open(file)
        image.thumbnail((800, 800))  # Resize the image

        # Save processed image to a BytesIO object
        img_byte_arr = io.BytesIO()
        image.save(img_byte_arr, format="JPEG")
        img_byte_arr = img_byte_arr.getvalue()
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config["UPLOAD_PATH"], filename)

        # Save the processed image to the file system or cloud storage
        with open(file_path, "wb") as f:
            f.write(img_byte_arr)

        # Placeholder values for new fields
        category_id = request.form.get("category_id", "default_category_id")
        sub_category = request.form.get("sub_category", "default_sub_category")
        tags = request.form.get("tags", "default_tag").split(
            ","
        )  

        # Updated clothes document with new fields
        clothes_document = {
            "file_path": file_path,
            "category": category,
            "category_id": category_id,
            "sub_category": sub_category,
            "tags": tags,
            "type": clothe_type,
            "color": color,
            "brand": brand,
            "occasion": occasion,
            "user_id": request.form.get(
                "user_id"
            ),
        }
        result = clothes_collection.insert_one(clothes_document)

        return jsonify(
            {"message": "File successfully uploaded", "file_path": file_path}
        ), 201
    else:
        return jsonify({"error": "Allowed file types are .jpg, .png, .jpeg"}), 400


# logic to handle uploaded file information
def add_clothe_to_db(user_id, file_path, category):
    clothe_data = {"user_id": user_id, "file_path": file_path, "category": category}
    # 'clothe_pictures' is your collection for storing clothes information
    mydb["clothe_pictures"].insert_one(clothe_data)


# Register_Page API
>>>>>>> Stashed changes
=======
# Register_Page API
>>>>>>> Stashed changes
@app.route("/Register", methods=["POST"])
# @limiter.limit("5 per minute")
def register():
    try:
        content = RegisterSchema().load(request.get_json())
<<<<<<< Updated upstream
    except ValidationError as err:
        return jsonify(err.messages), 400

<<<<<<< Updated upstream
# Check if user already exists
=======
    # Check if user already exists
>>>>>>> Stashed changes
    existing_user = mycol.find_one({"email": content["email"]})
    if existing_user:
        return jsonify({"error": "User with this email already exists"}), 409

<<<<<<< Updated upstream
#Hashing the password before saving
    hashed_password = generate_password_hash(content["password"], method='pbkdf2:sha256')
    content["password"] = hashed_password

#upon successful registration
=======
    # Hashing the password before saving
    hashed_password = generate_password_hash(
        content["password"], method="pbkdf2:sha256"
    )
    content["password"] = hashed_password

    # upon successful registration
>>>>>>> Stashed changes
    mycol.insert_one(content)
    return jsonify({"message": "User registered successfully!"}), 200
=======
        
        # Check if user already exists
        existing_user = mycol.find_one({"email": content["email"]})
        if existing_user:
            return jsonify({"error": "User with this email already exists"}), 409

        # Hash the password
        hashed_password = generate_password_hash(content["password"], method="pbkdf2:sha256")
        # Create user document
        user_document = {
        "email": content["email"],
        "password": content["password"],
        "fname": content.get("fname"),
        "lname": content.get("lname"),
        "dob": content.get("dob"),
        "gender": content.get("gender"),
        "location": content.get("location"),
        "phone": content.get("phone"),
        "size_preferences": content.get("size_preferences", ""),
        "style_preferences": content.get("style_preferences", [])
    }
        # Insert user into the database
        user_id = mycol.insert_one(user_document).inserted_id

        # Create a token for the new user
        token = create_token(str(user_id))
        if token is None:
            raise Exception("Failed to create token")

        return jsonify({
            "message": "User registered successfully!",
            "token": token
        }), 200

    except ValidationError as err:
        return jsonify(err.messages), 400
    except Exception as e:
        app.logger.error(f"An error occurred in /Register: {str(e)}")
        return jsonify({"error": "An internal error occurred"}), 500
>>>>>>> Stashed changes

<<<<<<< Updated upstream
#Login_Page API
=======

# Login_Page API
<<<<<<< Updated upstream
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes
@app.route("/Login", methods=["POST"])
# @limiter.limit("10 per minute")
def login():
<<<<<<< Updated upstream
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

<<<<<<< Updated upstream
        # If email and password are verified, you can add additional logic here
        # ...

=======
        # If email and password are verified
>>>>>>> Stashed changes
        return jsonify({"message": "Login successful!"}), 200

    except pymongo.errors.OperationFailure as e:
        return jsonify({"error": "Database operation failed"}), 500
    except Exception as e:
        return jsonify({"error": "An error occurred"}), 500


<<<<<<< Updated upstream

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
=======
# Logout API
@app.route("/Logout", methods=["POST"])
def logout():
    # Clear user session
    session.clear()
    return jsonify({"message": "Logout successful"})


# Profile_Setup API
@app.route("/ProfileSetup", methods=["POST"])
def profile_setup():
    content = request.get_json()
    session["email"] = content["email"]

    # Include new fields in profile setup
    profile_fields = [
        "first_name",
        "last_name",
        "dob",
        "gender",
        "phone",
        "size_preferences",
        "style_preferences",
    ]
    profile_data = {
        field: content.get(field) for field in profile_fields if field in content
    }

    # Update database with new profile data
    mycol.update_one({"email": content["email"]}, {"$set": profile_data})
    return jsonify({"message": "Profile set up successfully!"}), 200


class UpdateUserSchema(Schema):
    first_name = fields.Str(missing=None)
    last_name = fields.Str(missing=None)
    dob = fields.Date(missing=None)
    gender = fields.Str(missing=None)
    phone = fields.Str(missing=None)
    size_preferences = fields.Str(missing=None)
    style_preferences = fields.Str(missing=None)


# Update_Profile API
@app.route("/UpdateProfile", methods=["POST"])
def update_profile():
    user_id = request.json.get("user_id")

    # Validate updated data
>>>>>>> Stashed changes
    try:
        updated_data = UpdateUserSchema().load(request.json.get("updated_data", {}))
    except ValidationError as err:
        return jsonify(err.messages), 400

    # Update user profile in database
    mycol.update_one({"_id": user_id}, {"$set": updated_data})
    return jsonify({"message": "Profile updated successfully"}), 200

=======
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

        # If email and password are verified
        return jsonify({"message": "Login successful!"}), 200

    except pymongo.errors.OperationFailure as e:
        return jsonify({"error": "Database operation failed"}), 500
    except Exception as e:
        return jsonify({"error": "An error occurred"}), 500
>>>>>>> Stashed changes

# Google OAuth Login
@app.route('/login/google')
def google_login():
    flow = Flow.from_client_config(
        client_config={
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token"
            }
        },
        scopes=['https://www.googleapis.com/auth/calendar.readonly'],
        redirect_uri=GOOGLE_REDIRECT_URI
    )
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)

# Google OAuth Callback
@app.route('/login/google/callback')
def google_callback():
    state = session['state']
    flow = Flow.from_client_config(
        client_config={
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token"
            }
        },
        scopes=['https://www.googleapis.com/auth/calendar.readonly'],
        state=state,
        redirect_uri=GOOGLE_REDIRECT_URI
    )
    flow.fetch_token(authorization_response=request.url)

<<<<<<< Updated upstream
<<<<<<< Updated upstream
        # Update user's session
        session['user'] = user
        return jsonify({'message': 'Login with Google successful'})
    
    except ValueError:
        return jsonify({'message': 'Invalid ID token'})
    
=======
=======
>>>>>>> Stashed changes
    # Store credentials in the session or database
    credentials = flow.credentials
    session['google_credentials'] = credentials_to_dict(credentials)

    return redirect(url_for('index'))  # or your dashboard page

def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

<<<<<<< Updated upstream
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes

# Facebook login route
@app.route("/Login/facebook", methods=["POST"])
def login_with_facebook():
<<<<<<< Updated upstream
<<<<<<< Updated upstream
    access_token = request.json['access_token']
    app_id = config('FACEBOOK_APP_ID')  # replaced with config
    app_secret = config('FACEBOOK_APP_SECRET')  # replaced with config
=======
    access_token = request.json["access_token"]
    app_id = config("FACEBOOK_APP_ID")  # replaced with config
    app_secret = config("FACEBOOK_APP_SECRET")  # replaced with config
>>>>>>> Stashed changes
=======
    access_token = request.json["access_token"]
    app_id = config("FACEBOOK_APP_ID")  # replaced with config
    app_secret = config("FACEBOOK_APP_SECRET")  # replaced with config
>>>>>>> Stashed changes
    try:
        # Verify the Facebook access token
        params = {
            "access_token": access_token,
            "appsecret_proof": generate_appsecret_proof(app_secret, access_token),
        }
        response = request.get(
            f"https://graph.facebook.com/v13.0/debug_token?input_token={access_token}",
            params=params,
        )
        data = response.json()

        if "error" in data or not data["data"]["is_valid"]:
            raise ValueError("Invalid access token")

        # Check if user is already registered
        user_id = data["data"]["user_id"]
        user = mycol.find_one({"facebook_id": user_id})
        if not user:
            # User is not registered, perform registration logic here

            # Create a new user document
            user = {
<<<<<<< Updated upstream
<<<<<<< Updated upstream
                'facebook_id': user_id,
                'password': None  # No password for Facebook login

=======
                "facebook_id": user_id,
                "password": None,  # No password for Facebook login
>>>>>>> Stashed changes
=======
                "facebook_id": user_id,
                "password": None,  # No password for Facebook login
>>>>>>> Stashed changes
            }

            # Insert the user document into the users collection
            mycol.insert_one(user)

        # Update user's session
        session["user"] = user

        return jsonify({"message": "Login with Facebook successful"})
    except ValueError:
        return jsonify({"message": "Invalid access token"})
<<<<<<< Updated upstream
=======


#profile setup
@app.route("/ProfileSetup", methods=["POST"])
@login_required
def profile_setup(current_user):
    email = request.json.get("email")
    dob = request.json.get("dob")  # Make sure to get data from request.json
    gender = request.json.get("gender")

    # Update the user document
    mydb["User"].update_one({"email": email}, {"$set": {"dob": dob, "gender": gender}})

    return jsonify({"message": "Profile updated successfully"}), 200

@app.route("/WeatherSetup", methods=["POST"])
@login_required
def weather_setup(current_user):
    email = request.json.get("email")
    location = request.json.get("location")  # Make sure to get data from request.json

    # Update the user document
    mydb["User"].update_one({"email": email}, {"$set": {"location": location}})

    return jsonify({"message": "Weather updated successfully"}), 200

# Update_Profile API
@app.route("/UpdateProfile", methods=["POST"])
@login_required
def update_profile(current_user):
    user_id = request.json.get("user_id")

    # Validate updated data
    try:
        updated_data = UpdateUserSchema().load(request.json.get("updated_data", {}))
    except ValidationError as err:
        return jsonify(err.messages), 400

    # Update user profile in database
    mycol.update_one({"_id": user_id}, {"$set": updated_data})
    return jsonify({"message": "Profile updated successfully"}), 200



@app.route('/upload_profile_photo', methods=['POST'])
@login_required
def upload_profile_photo(current_user):
    user_id = request.json.get("user_id")
    if 'photo' not in request.files:
        return jsonify({'error': 'No photo part'}), 400
    file = request.files['photo']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_PATH'], filename)

        # Resize and save the image
        image = Image.open(file)
        image.thumbnail((300, 300))  # Resize to 300x300 pixels
        image.save(file_path)

        # Update user's profile in MongoDB
        mycol.update_one({'_id': user_id}, {'$set': {'profile_photo': file_path}})

        return jsonify({'message': 'Profile photo uploaded successfully'}), 200
    else:
        return jsonify({'error': 'Invalid file type'}), 400
    

# Logout API
@app.route("/Logout", methods=["POST"])
def logout():
    # Clear user session
    session.clear()
    return jsonify({"message": "Logout successful"})



# @app.route("/upload_clothe", methods=["POST"])
# def upload_clothe():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files["file"]

    # Validate form data
    try:
        data = ClothesUploadSchema().load(request.form)
    except ValidationError as err:
        return jsonify(err.messages), 400

    # Get the tags and other details from the User
    category = request.form.get("category")
    clothe_type = request.form.get("type")
    color = request.form.get("color")
    brand = request.form.get("brand")
    occasion = request.form.get("occasion")
    if not category:
        return jsonify({"error": "No category provided"}), 400
    if file.filename == "":
        return jsonify({"error": "No file selected for uploading"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "Allowed file types are .jpg, .png, .jpeg"}), 400
    if file and allowed_file(file.filename):
        
        # Image processing
        image = Image.open(file)
        image.thumbnail((800, 800))  # Resize the image

        # Save processed image to a BytesIO object
        img_byte_arr = io.BytesIO()
        image.save(img_byte_arr, format="JPEG")
        img_byte_arr = img_byte_arr.getvalue()
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config["UPLOAD_PATH"], filename)
        

        # Save the processed image to the file system or cloud storage
        with open(file_path, "wb") as f:
            f.write(img_byte_arr)

        # Placeholder values for new fields
        category_id = request.form.get("category_id", "default_category_id")
        sub_category = request.form.get("sub_category", "default_sub_category")
        tags = request.form.get("tags", "default_tag").split(
            ","
        )  

        # Updated clothes document with new fields
        clothes_document = {
            "file_path": file_path,
            "category": category,
            "category_id": category_id,
            "sub_category": sub_category,
            "tags": tags,
            "type": clothe_type,
            "color": color,
            "brand": brand,
            "occasion": occasion,
            "user_id": request.form.get(
                "user_id"
            ),
        }
        result = clothes_collection.insert_one(clothes_document)

        user_id = request.form.get("user_id")
        category = request.form.get("category")

        # Update the user document with the new image path
        mydb["User"].update_one(
            {"_id": user_id},
            {"$set": {f"category_images.{category}": file_path}}
        )

        return jsonify({"message": "File successfully uploaded", "file_path": file_path}), 201
    else:
        return jsonify({"error": "Allowed file types are .jpg, .png, .jpeg"}), 400


@app.route("/upload_clothe", methods=["POST"])
def upload_clothe():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files["file"]
    category = request.form.get("category")
    email = request.form.get("email")

    if not category or not email:
        return jsonify({"error": "Category or Email not provided"}), 400

    # Find user by email
    user = mydb["User"].find_one({"email": email})
    if not user:
        return jsonify({"error": "User not found"}), 404
    user_id = user["_id"]

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config["UPLOAD_PATH"], filename)
        file.save(file_path)

        # Update user's document in MongoDB
        update_result = mydb["User"].update_one(
            {"_id": user_id},
            {"$push": {f"clothes.{category}": file_path}}
        )

        if update_result.modified_count == 0:
            return jsonify({"error": "User not found or update failed"}), 404

        return jsonify({"message": "File successfully uploaded", "file_path": file_path}), 201

    else:
        return jsonify({"error": "No file selected for uploading or invalid file type"}), 400



@app.route("/get_user_category_images", methods=["GET"])
def get_user_category_images():
    email = request.args.get("email")
    category = request.args.get("category")

    # Debugging: Print the received email and category
    print(f"Email: {email}, Category: {category}")

    user = mydb["User"].find_one({"email": email})
    
    # Debugging: Check if the user was found
    if not user:
        print("User not found in the database")
        return jsonify({"error": "User not found"}), 404

    # Extract image file paths for the specified category
    image_paths = user.get("clothes", {}).get(category, [])

    # Convert local paths to URLs
    image_urls = [convert_to_url(path) for path in image_paths]

    return jsonify(image_urls), 200

def convert_to_url(local_path):
    # Implement conversion from local path to accessible URL
    base_url = 'https://4581-2001-1970-5d9c-4d00-4434-94d6-3fb9-4fc.ngrok-free.app/resources/'
    filename = os.path.basename(local_path)
    return os.path.join(base_url, filename)



@app.route("/get_category_images", methods=["GET"])
def get_category_images():
    user_id = request.args.get("user_id")

    # Fetch the user document and return the category images
    user = mydb["User"].find_one({"_id": user_id}, {"category_images": 1})
    if user and "category_images" in user:
        return jsonify(user["category_images"]), 200
    else:
        return jsonify({"error": "User not found or no category images available"}), 404


# logic to handle uploaded file information
def add_clothe_to_db(user_id, file_path, category):
    clothe_data = {"user_id": user_id, "file_path": file_path, "category": category}
    # 'clothe_pictures' is your collection for storing clothes information
    mydb["clothe_pictures"].insert_one(clothe_data)



@app.route("/get_categories", methods=["GET"])
def get_categories():
    categories = mydb["categories"].find({})  # Assuming 'categories' is your collection
    categories_list = []
    for category in categories:
        categories_list.append({
            "name": category["name"],
            "image_url": category.get("image_url", "default_image.png")  # Default image if not set
        })
    return jsonify(categories_list), 200





>>>>>>> Stashed changes


def generate_appsecret_proof(app_secret, access_token):
    import hmac
    import hashlib

    key = app_secret.encode("utf-8")
    msg = access_token.encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()

<<<<<<< Updated upstream
#Forgot_Password route
=======

# Forgot_Password route
<<<<<<< Updated upstream
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes
@app.route("/forgot_password", methods=["POST"])
def forgot_password():
    email = request.json["email"]
    user = mycol.find_one({"email": email})
<<<<<<< Updated upstream
    if not user:
        return jsonify({"message": "Email not found"}), 404

    token = generate_reset_token(email)
<<<<<<< Updated upstream
    
    #Send an email with the token using SendGrid
    message = Mail(
        from_email='171080107009.acet@gmail.com',
        to_emails=email,
        subject='Password Reset Request',
        html_content=f'''
=======

    # Send an email with the token using SendGrid
    message = Mail(
        from_email="171080107009.acet@gmail.com",
        to_emails=email,
        subject="Password Reset Request",
        html_content=f"""
>>>>>>> Stashed changes
        To reset your password, visit the following link:
        http://127.0.0.1:5000/forgot_password?token={token}

        If you did not make this request, then simply ignore this email and no changes will be made.
<<<<<<< Updated upstream
        ''')
    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
=======
        """,
    )
    try:
        sg = SendGridAPIClient(os.environ.get("SENDGRID_API_KEY"))
>>>>>>> Stashed changes
        response = sg.send(message)
    except Exception as e:
        print(e)
        return jsonify({"error": "An error occurred while sending the email"}), 500

<<<<<<< Updated upstream
    return jsonify({'message': 'Password reset email sent!'})
    email = request.json['email']
    user = mycol.find_one({'email': email})
=======
>>>>>>> Stashed changes
    if not user:
        return jsonify({"message": "Email not found"}), 404

    token = generate_reset_token(email)
<<<<<<< Updated upstream
    
    #Send an email with the token
    msg = Message('Password Reset Request', sender='171080107009.acet@gmail.com', recipients=[email])
    msg.body = f'''
=======
=======

    # Send an email with the token using SendGrid
    message = Mail(
        from_email="171080107009.acet@gmail.com",
        to_emails=email,
        subject="Password Reset Request",
        html_content=f"""
        To reset your password, visit the following link:
        http://127.0.0.1:5000/forgot_password?token={token}

        If you did not make this request, then simply ignore this email and no changes will be made.
        """,
    )
    try:
        sg = SendGridAPIClient(os.environ.get("SENDGRID_API_KEY"))
        response = sg.send(message)
    except Exception as e:
        print(e)
        return jsonify({"error": "An error occurred while sending the email"}), 500

>>>>>>> Stashed changes
    return jsonify({"message": "Password reset email sent!"})
    email = request.json["email"]
    user = mycol.find_one({"email": email})
    if not user:
        return jsonify({"message": "Email not found"}), 404

    token = generate_reset_token(email)

    # Send an email with the token
    msg = Message(
        "Password Reset Request",
        sender="171080107009.acet@gmail.com",
        recipients=[email],
    )
    msg.body = f"""
<<<<<<< Updated upstream
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes
    To reset your password, visit the following link:
    YOUR_FLUTTER_APP_RESET_LINK?token={token}

    If you did not make this request, then simply ignore this email and no changes will be made.
    """
    mail.send(msg)

    return jsonify({"message": "Password reset email sent!"})


def generate_reset_token(email, expiration=1800):
    s = URLSafeTimedSerializer(app.secret_key)
    return s.dumps(email, salt="password-reset-salt")


def verify_reset_token(token, expiration=1800):
    s = URLSafeTimedSerializer(app.secret_key)
    try:
        email = s.loads(token, salt="password-reset-salt", max_age=expiration)
    except:  # noqa: E722
        return None
    return email


<<<<<<< Updated upstream
<<<<<<< Updated upstream
@app.route('/import_clothes_data', methods=['POST'])
def import_clothes_data():
    file_path = 'clothes_data.json'  # Replace with your actual JSON file path
    with open(file_path, 'r') as file:
=======
# Authenticate Decorator for routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


=======
>>>>>>> Stashed changes
@app.route("/import_clothes_data", methods=["POST"])
def import_clothes_data():
    file_path = "clothes_data.json"  # Replace with your actual JSON file path
    with open(file_path, "r") as file:
<<<<<<< Updated upstream
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes
        data = json.load(file)
        try:
            # Insert data into the MongoDB collection
            result = clothes_collection.insert_many(data)
<<<<<<< Updated upstream
<<<<<<< Updated upstream
            return jsonify({'message': f'{result.inserted_ids} records inserted successfully!'}), 201
        except BulkWriteError as bwe:
            # Return detailed error message if a BulkWriteError occurs
            return jsonify({'error': str(bwe.details)}), 500


@app.route('/import_user_data', methods=['POST'])
def import_user_data():
    file_path = 'expanded_users_data.json'  # Replace with your actual JSON file path
    with open(file_path, 'r') as file:
=======
=======
>>>>>>> Stashed changes
            return jsonify(
                {"message": f"{result.inserted_ids} records inserted successfully!"}
            ), 201
        except BulkWriteError as bwe:
            # Return detailed error message if a BulkWriteError occurs
            return jsonify({"error": str(bwe.details)}), 500


@app.route("/import_user_data", methods=["POST"])
def import_user_data():
    file_path = "expanded_users_data.json"  # Replace with your actual JSON file path
    with open(file_path, "r") as file:
<<<<<<< Updated upstream
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes
        data = json.load(file)
        try:
            # Attempt to insert data into the MongoDB collection
            result = mycol.insert_many(data, ordered=False)
<<<<<<< Updated upstream
<<<<<<< Updated upstream
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
=======
=======
>>>>>>> Stashed changes
            return jsonify(
                {
                    "message": f"{len(result.inserted_ids)} records inserted successfully!"
                }
            ), 201
        except BulkWriteError as bwe:
            # Return detailed error message if a BulkWriteError occurs
            return jsonify({"error": str(bwe.details)}), 500


@app.route("/get_weather", methods=["GET"])
def get_weather(city=None):
    city = city or request.args.get(
        "city", "Windsor"
    )  # Default to Windsor if no city is provided

    # OpenWeatherMap API endpoint with city
    url = f"http://api.openweathermap.org/data/2.5/weather?q={city}&appid={OPENWEATHER_API_KEY}&units=metric"
<<<<<<< Updated upstream
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes

    try:
        response = requests.get(url)
        response.raise_for_status()  # Will raise an HTTPError if the HTTP request returned an unsuccessful status code

        data = response.json()

        # Create a document to save in the database
        weather_document = {
<<<<<<< Updated upstream
<<<<<<< Updated upstream
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
=======
=======
>>>>>>> Stashed changes
            "city": city,
            "temperature": data["main"]["temp"],
            "weather_conditions": data["weather"][0]["description"],
            "last_updated": datetime.datetime.utcnow(),  # Store the current time
        }

        # Save or update the document in the database
        mydb["weather_data"].update_one(
            {"city": city}, {"$set": weather_document}, upsert=True
        )

        return jsonify(
            {
                "temperature": weather_document["temperature"],
                "weather_conditions": weather_document["weather_conditions"],
            }
        ), 200

    except requests.exceptions.HTTPError as errh:
        return jsonify({"error": f"HTTP Error: {errh}"}), errh.response.status_code
    except requests.exceptions.ConnectionError as errc:
        return jsonify({"error": f"Error Connecting: {errc}"}), 500
    except requests.exceptions.Timeout as errt:
        return jsonify({"error": f"Timeout Error: {errt}"}), 500
    except requests.exceptions.RequestException as err:
        return jsonify({"error": f"Error: {err}"}), 500


# Define the function to update weather data
def update_weather_data():
    cities = ["Windsor", "London", "Cambridge"]  # Add your list of cities here

    for city in cities:
        try:
            # Call get_weather function and pass the city as a parameter
            response = get_weather(city)
            if response.status_code == 200:
                weather_data = response.json()

                # Update the database with the new weather data
                mydb["weather_data"].update_one(
                    {"city": city},
                    {
                        "$set": {
                            "temperature": weather_data["temperature"],
                            "weather_conditions": weather_data["weather_conditions"],
                            "last_updated": datetime.datetime.utcnow(),
                        }
                    },
                    upsert=True,
                )
            else:
                app.logger.error(
                    f"Failed to fetch weather data for {city}: {response.status_code}"
                )
        except Exception as e:
            app.logger.error(
                f"An error occurred while updating weather data for {city}: {str(e)}"
            )

<<<<<<< Updated upstream
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes

# Initialize the scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=update_weather_data, trigger="interval", hours=1)
scheduler.start()

# Ensure that the scheduler is shut down when exiting the app
atexit.register(lambda: scheduler.shutdown())


<<<<<<< Updated upstream
<<<<<<< Updated upstream
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
=======
@app.route("/add_favorite", methods=["POST"])
def add_favorite():
    user_id = request.json.get("user_id")
    clothe_id = request.json.get("clothe_id")
    # Add more fields if necessary

    # Insert into favorites collection
    mydb["favorites"].insert_one({"user_id": user_id, "clothe_id": clothe_id})
    return jsonify({"message": "Added to favorites"}), 200


@app.route("/get_favorites", methods=["GET"])
def get_favorites():
    user_id = request.args.get("user_id")

    favorites = mydb["favorites"].find({"user_id": user_id})
>>>>>>> Stashed changes
    favorite_items = [item for item in favorites]

    return jsonify(favorite_items), 200


<<<<<<< Updated upstream

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
=======
=======
@app.route("/delete_image", methods=["POST"])
@login_required
def delete_image(current_user):
    email = current_user["email"]
    image_path = request.json.get("image_path")  # Get the full path of the image
    category = request.json.get("category")  # Category of the image to delete

    # Fetch user document to ensure the image belongs to the user
    user = mycol.find_one({"email": email})

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Check if the image path is in the specified category in the user's document
    if category not in user.get("clothes", {}) or image_path not in user["clothes"][category]:
        return jsonify({"error": "Image not found in user's account"}), 404

    # Deleting the image reference from the user's document
    mycol.update_one({"email": email}, {"$pull": {f"clothes.{category}": image_path}})

    # Optional: Delete the actual image file from the server
    # This assumes you have saved your images in a directory and image_path is the filename
    if os.path.exists(image_path):
        os.remove(image_path)

    return jsonify({"message": "Image deleted successfully"}), 200


@app.route("/add_favorite", methods=["POST"])
@login_required
def add_favorite(current_user):
    email = current_user.get("email")
    if not email:
        app.logger.error("Email not found in current_user")
        return jsonify({"error": "User email not found"}), 400

    if not current_user:
        app.logger.error("Current user is None")
        return jsonify({"error": "Authentication failed"}), 401



    image_path = request.json.get("image_path")
    category = request.json.get("category")

    user = mycol.find_one({"email": email})
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Initialize favorites if not present
    if "favorites" not in user:
        user["favorites"] = {}

    # Add the image to the favorites under the correct category
    if category not in user["favorites"]:
        user["favorites"][category] = []

    if image_path not in user["favorites"][category]:
        mycol.update_one({"email": email}, {"$push": {f"favorites.{category}": image_path}})

    return jsonify({"message": "Added to favorites"}), 200


@app.route("/remove_favorite", methods=["POST"])
@login_required
def remove_favorite(current_user):
    email = current_user["email"]
    image_path = request.json.get("image_path")
    category = request.json.get("category")

    user = mycol.find_one({"email": email})
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Check if the image path is in the favorites
    if category not in user.get("favorites", {}) or image_path not in user["favorites"][category]:
        return jsonify({"error": "Image not found in favorites"}), 404

    # Removing the image from favorites
    mycol.update_one({"email": email}, {"$pull": {f"favorites.{category}": image_path}})

    return jsonify({"message": "Removed from favorites"}), 200


>>>>>>> Stashed changes
def recommend_clothes(user_id):
    # Example logic: find the most favorited category of clothes for this user
    favorite_category = mydb["favorites"].aggregate(
        [
            {"$match": {"user_id": user_id}},
            {"$group": {"_id": "$category", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 1},
        ]
    )

    if favorite_category:
        category = favorite_category[0]["_id"]
        recommended_items = mydb["clothes"].find({"category": category}).limit(10)
<<<<<<< Updated upstream
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes
        return [item for item in recommended_items]
    else:
        return []


<<<<<<< Updated upstream
<<<<<<< Updated upstream

@app.errorhandler(Exception)
def handle_exception(e):
    # logging the exception here for debugging purposes
    print(f"An error occurred: {str(e)}")
    return jsonify({'error': 'A server error occurred'}), 500
=======
# Category Management Endpoints
@app.route('/add_category', methods=['POST'])
@login_required
def add_category(current_user):
    try:
        data = CategorySchema().load(request.get_json())
    except ValidationError as err:
        return jsonify(err.messages), 400

    mydb['categories'].insert_one(data)
    return jsonify({'message': 'Category added successfully'}), 201

@app.route('/view_categories', methods=['GET'])
@login_required
def view_categories(current_user):
    categories = mydb['categories'].find({})
    return jsonify(list(categories)), 200

@app.route('/update_category/<category_id>', methods=['PUT'])
@login_required
def update_category(current_user, category_id):
    try:
        data = CategorySchema().load(request.get_json())
    except ValidationError as err:
        return jsonify(err.messages), 400

    mydb['categories'].update_one({'_id': category_id}, {'$set': data})
    return jsonify({'message': 'Category updated successfully'}), 200

@app.route('/delete_category/<category_id>', methods=['DELETE'])
@login_required
def delete_category(current_user, category_id):
    mydb['categories'].delete_one({'_id': category_id})
    return jsonify({'message': 'Category deleted successfully'}), 200



@app.errorhandler(Exception)
def handle_exception(e):
    # Log the exception with all details for debugging purposes
    app.logger.error(f"An error occurred: {str(e)}")

    # Return a generic error message
    return jsonify({"error": "An internal server error occurred"}), 500
>>>>>>> Stashed changes


if __name__ == "__main__":
    app.run(port=5000)
<<<<<<< Updated upstream
=======
# Category Management Endpoints
@app.route('/add_category', methods=['POST'])
@login_required
def add_category():
    try:
        data = CategorySchema().load(request.get_json())
    except ValidationError as err:
        return jsonify(err.messages), 400

    mydb['categories'].insert_one(data)
    return jsonify({'message': 'Category added successfully'}), 201

@app.route('/view_categories', methods=['GET'])
@login_required
def view_categories():
    categories = mydb['categories'].find({})
    return jsonify(list(categories)), 200

@app.route('/update_category/<category_id>', methods=['PUT'])
@login_required
def update_category(category_id):
    try:
        data = CategorySchema().load(request.get_json())
    except ValidationError as err:
        return jsonify(err.messages), 400

    mydb['categories'].update_one({'_id': category_id}, {'$set': data})
    return jsonify({'message': 'Category updated successfully'}), 200

@app.route('/delete_category/<category_id>', methods=['DELETE'])
@login_required
def delete_category(category_id):
    mydb['categories'].delete_one({'_id': category_id})
    return jsonify({'message': 'Category deleted successfully'}), 200



@app.errorhandler(Exception)
def handle_exception(e):
    # Log the exception with all details for debugging purposes
    app.logger.error(f"An error occurred: {str(e)}")

    # Return a generic error message
    return jsonify({"error": "An internal server error occurred"}), 500


if __name__ == "__main__":
    app.run(port=5000)
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes
