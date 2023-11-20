import os
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer

# Utility function to check if a file extension is allowed
def allowed_file(filename, allowed_extensions):
    return '.' in filename and \
           os.path.splitext(filename)[1].lower() in allowed_extensions

# Utility function for generating a reset token
def generate_reset_token(email, secret_key, salt='password-reset-salt', expiration=1800):
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.dumps(email, salt=salt)

# Utility function for verifying a reset token
def verify_reset_token(token, secret_key, salt='password-reset-salt', expiration=1800):
    serializer = URLSafeTimedSerializer(secret_key)
    try:
        email = serializer.loads(token, salt=salt, max_age=expiration)
    except:
        return None
    return email

# Function for secure file naming
def get_secure_filename(filename):
    return secure_filename(filename)
