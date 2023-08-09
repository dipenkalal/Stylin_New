from flask import Flask
from flask_mail import Mail
from pymongo import MongoClient
from flask_sqlalchemy import SQLAlchemy
import os

# Create the Flask app
app = Flask(__name__)
app.secret_key = '123456789'
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'patelnency1210'
# app.config['MAIL_PASSWORD'] = 'zfyfkqkradzpcpza'
app.config['MAIL_DEFAULT_SENDER'] = 'patelnency1210@gmail.com'

# Initialize Flask Mail
mail = Mail(app)
# Initialize SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///image_details.db'  # SQLite database file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define the Image model using SQLAlchemy
class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    categories = db.Column(db.String(100), nullable=False)
    material = db.Column(db.String(100), nullable=False)
    pattern = db.Column(db.String(100), nullable=False)
    brand = db.Column(db.String(100), nullable=False)
    color = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f"<Image {self.filename}>"
# MongoDB configuration
uri = "mongodb://localhost:27017"
client = MongoClient(uri)
db = client['Authentication']
users_collection = db['User']

# Import routes from separate files
from auth_routes import auth_routes
from image_routes import image_routes
# from shopping_data import shopping_data
# Register blueprints for routes
app.register_blueprint(auth_routes)
app.register_blueprint(image_routes)
# app.register_blueprint(shopping_data)

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    db.create_all()    
    app.run(host='localhost', port=5000)
