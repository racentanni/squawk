# utils.py
import os
from werkzeug.utils import secure_filename
from flask import current_app
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

def save_image(image):
    """Save uploaded image and return its path."""
    if not image or isinstance(image, str):
        # If no file is uploaded or the input is a string, return the input as-is
        return image

    filename = secure_filename(image.filename)
    filepath = os.path.join(current_app.root_path, 'static/uploads', filename)
    image.save(filepath)
    return f"/static/uploads/{filename}"

def generate_reset_token(user, expires_sec=3600):
    """Generate a password reset token."""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(user.id, salt='password-reset-salt')

def verify_reset_token(token):
    """Verify the password reset token."""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        user_id = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except (SignatureExpired, BadSignature):
        return None
    from models import User  # Import here to avoid circular imports
    return User.query.get(user_id)