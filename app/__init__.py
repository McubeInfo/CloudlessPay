from flask import Flask
from flask_cors import CORS
from flask_migrate import Migrate
from app.config import db, jwt

def create_app():
    
    app = Flask(__name__)
    app.config.from_prefixed_env()
    CORS(app) 
          
    db.init_app(app)
    jwt.init_app(app)
    
    migrate = Migrate(app, db)
    
    from app.create_orders import order_bp
    from app.auth import auth_bp
    from app.users import user_bp
    from app.main import main_bp
    from app.logs import logs_bp
    from app.settings import settings_bp
    
    app.register_blueprint(order_bp, url_prefix='/api')
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(user_bp, url_prefix='/users')
    app.register_blueprint(main_bp)
    app.register_blueprint(logs_bp, url_prefix='/api')
    app.register_blueprint(settings_bp, url_prefix='/settings')
    
    return app