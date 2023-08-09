from flask import Blueprint, Flask, request, jsonify, send_file, session
from werkzeug.utils import secure_filename
import os
from flask_sqlalchemy import SQLAlchemy

# Create a Flask app
app = Flask(__name__)
app.secret_key = '123456789'
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')  # Update with the path to your upload folder
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Define the allowed image extensions

# Initialize SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///image_details.db'  # SQLite database file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define the Image model using SQLAlchemy
class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f"<Image {self.filename}>"

def allowed_file(filename):
    # Check if the file extension is allowed
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

image_routes = Blueprint('image_routes', __name__)

@image_routes.route('/upload', methods=['POST'])
def upload_image():
    # Check if a file is included in the request
    if 'image' not in request.files:
        return jsonify({'message': 'No file included in the request'})

    file = request.files['image']
    # Check if the file is allowed
    if not allowed_file(file.filename):
        return jsonify({'message': 'Invalid file type'})

    # Generate a secure filename
    filename = secure_filename(file.filename)
    # Save the file to the upload folder
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    # Store the image filename in the database
    new_image_entry = Image(filename=filename)
    db.session.add(new_image_entry)
    db.session.commit()

    return jsonify({'message': 'Image uploaded successfully'})

@image_routes.route('/images', methods=['GET'])
def get_images():
    # Get a list of all image files in the upload folder
    image_files = [f for f in os.listdir(app.config['UPLOAD_FOLDER']) if os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], f))]

    # Return the list of image files
    return jsonify({'images': image_files})

@image_routes.route('/images/<image_id>', methods=['GET'])
def get_image(image_id):
    # Check if the image file exists
    if not os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], image_id)):
        return jsonify({'message': 'Image not found'})

    # Send the image file as a response
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], image_id), mimetype='image/jpeg')  # Adjust the mimetype if needed

@image_routes.route('/get_images', methods=['GET'])
def get_images():
    # Get query parameters for categories
    categories = request.args.getlist('category')

    # Get a list of all image files in the upload folder
    image_files = [f for f in os.listdir(app.config['UPLOAD_FOLDER']) if os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], f))]

    # Filter images based on categories
    if categories:
        image_files = [f for f in image_files if any(category.lower() in f.lower() for category in categories)]

    
    logged_in_user_gender = session.get('gender')  

    # If the user is female, include only images with the "dress" category
    if logged_in_user_gender == 'female' and 'dresses' not in categories:
        image_files = [f for f in image_files if 'dress' in f.lower()]

    # Return the list of filtered image files
    return jsonify({'images': image_files})