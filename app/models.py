from app.database import db
from datetime import datetime
from flask_login import UserMixin  # Import UserMixin to simplify implementation

class User(UserMixin, db.Model):  # Inherit from UserMixin
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    verification_status = db.Column(db.String(20), nullable=True)

    # flask_login required methods (provided by UserMixin)
    # UserMixin implements is_authenticated, is_active, is_anonymous, and get_id
    # Customize is_active if needed based on verification_status
    def is_active(self):
        return self.verification_status == 'approved'  # Only active if approved

class Post(db.Model):
    __tablename__ = 'post'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(200), nullable=True)
    days_left = db.Column(db.Integer, nullable=True)
    priority = db.Column(db.String(20), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)