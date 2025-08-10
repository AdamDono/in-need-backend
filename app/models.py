from datetime import datetime

class User:
    def __init__(self, db):
        self.id = db.Column(db.Integer, primary_key=True)
        self.username = db.Column(db.String(100), nullable=False)
        self.email = db.Column(db.String(120), unique=True, nullable=False)
        self.password_hash = db.Column(db.String(128), nullable=False)
        self.role = db.Column(db.String(20), nullable=False)  # sponsor, organization, individual
        self.name = db.Column(db.String(100), nullable=False)
        self.created_at = db.Column(db.DateTime, default=datetime.utcnow)
        self.verification_status = db.Column(db.String(20), default='approved' if self.role == 'sponsor' else 'pending')

class Post:
    def __init__(self, db):
        self.id = db.Column(db.Integer, primary_key=True)
        self.user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        self.title = db.Column(db.String(200), nullable=False)
        self.description = db.Column(db.Text, nullable=False)
        self.image_url = db.Column(db.String(200))
        self.days_left = db.Column(db.Integer)
        self.priority = db.Column(db.String(20))  # e.g., High Priority, Low Priority
        self.created_at = db.Column(db.DateTime, default=datetime.utcnow)