from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from .config import Config
from datetime import datetime  # Added this import
from werkzeug.security import generate_password_hash

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__, template_folder='../../in-needfrontend/templates', static_folder='../../in-needfrontend/static')
    app.config.from_object(Config)
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'

    class User(db.Model):
        __tablename__ = 'user'
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(100), nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False)
        password_hash = db.Column(db.String(128), nullable=False)
        role = db.Column(db.String(20), nullable=False)  # sponsor, organization, individual
        name = db.Column(db.String(100), nullable=False)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        verification_status = db.Column(db.String(20), default='approved' if role == 'sponsor' else 'pending')

    class Post(db.Model):
        __tablename__ = 'post'
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        title = db.Column(db.String(200), nullable=False)
        description = db.Column(db.Text, nullable=False)
        image_url = db.Column(db.String(200))
        days_left = db.Column(db.Integer)
        priority = db.Column(db.String(20))
        created_at = db.Column(db.DateTime, default=datetime.utcnow)

    from .routes import main
    app.register_blueprint(main)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @app.cli.command('create-admin')
    def create_admin():
        admin = User(username='admin', email='admin@example.com', password_hash=generate_password_hash('secret', method='pbkdf2:sha256'), role='admin', name='Admin', verification_status='approved')
        db.session.add(admin)
        db.session.commit()
        print('Admin user created successfully.')

    return app