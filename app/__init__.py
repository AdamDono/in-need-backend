from flask import Flask
from flask_migrate import Migrate
from flask_login import LoginManager
from .config import Config
from .database import db
from werkzeug.security import generate_password_hash
import base64

migrate = Migrate()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__, template_folder='../../in-needfrontend/templates', static_folder='../../in-needfrontend/static')
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'

    with app.app_context():
        from .models import User, Post

    from .routes import main
    app.register_blueprint(main)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @app.cli.command('create-admin')
    def create_admin():
        from .models import User
        admin = User(username='admin', email='admin@example.com', password_hash=generate_password_hash('secret', method='pbkdf2:sha256'), role='admin', name='Admin', verification_status='approved')
        db.session.add(admin)
        db.session.commit()
        print('Admin user created successfully.')

    @app.template_filter('to_base64')
    def to_base64(binary):
        if binary:
            return base64.b64encode(binary).decode('utf-8')
        return ''

    @app.template_filter('multiply')
    def multiply(value, factor):
        return value * factor

    return app