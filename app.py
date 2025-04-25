import os
import logging

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_login import LoginManager


# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create SQLAlchemy base class
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy
db = SQLAlchemy(model_class=Base)

# Initialize Flask-Login
login_manager = LoginManager()

# Create Flask application
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # needed for url_for to generate with https

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize the app with the SQLAlchemy extension
db.init_app(app)

# Configure Flask-Login
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))

# Import routes and initialize app
with app.app_context():
    # Import models
    import models  # noqa: F401
    import views
    
    # Register the view routes
    app.add_url_rule('/', 'index', views.index)
    app.add_url_rule('/register', 'register', views.register, methods=['GET', 'POST'])
    app.add_url_rule('/login', 'login', views.login, methods=['GET', 'POST'])
    app.add_url_rule('/logout', 'logout', views.logout)
    app.add_url_rule('/dashboard', 'dashboard', views.dashboard)
    app.add_url_rule('/add-password', 'add_password', views.add_password, methods=['GET', 'POST'])
    app.add_url_rule('/password/<int:id>', 'view_password', views.view_password, methods=['GET', 'POST'])
    app.add_url_rule('/generate-password', 'generate_password', views.generate_password, methods=['GET', 'POST'])
    app.add_url_rule('/password/edit/<int:id>', 'edit_password', views.edit_password, methods=['GET', 'POST'])
    app.add_url_rule('/password/delete/<int:id>', 'delete_password', views.delete_password)
    
    # Create database tables
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
