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


#initializing the app
app = Flask(__name__)
app.secret_key = config('SECRET_KEY')
cors = CORS(app)
app.config["CORS_HEADERS"] = "content-type"