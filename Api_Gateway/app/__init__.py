from flask import Flask
from flask_cors import CORS
from flask_caching import Cache

cache = Cache()  # Create the Cache object

def create_app():
    app = Flask(__name__)

    # Enable CORS for specific origins
    CORS(app, resources={r"/api/*": {"origins": "http://172.16.0.75:8080"}})

    # Configure caching
    app.config.from_object('config.Config')
    cache.init_app(app)  # Initialize Cache with the app

    # Register Blueprints
    from .routes.alerts import alerts_bp
    from .routes.count import count_bp
    from .routes.tags import tags_bp
    from .routes.users import users_bp
    from .routes.computers import computers_bp
    from .routes.outliers import outliers_bp
    from .routes.timeline import timeline_bp
    from .routes.logs import logs_bp
    from .routes.highrisk_users_outliers import highrisk_bp  # Import the new highrisk blueprint

    app.register_blueprint(alerts_bp, url_prefix='/api')
    app.register_blueprint(count_bp, url_prefix='/api')
    app.register_blueprint(tags_bp, url_prefix='/api')
    app.register_blueprint(users_bp, url_prefix='/api')
    app.register_blueprint(computers_bp, url_prefix='/api')
    app.register_blueprint(outliers_bp, url_prefix='/api')
    app.register_blueprint(timeline_bp, url_prefix='/api')
    app.register_blueprint(logs_bp, url_prefix='/api')
    app.register_blueprint(highrisk_bp, url_prefix='/api')  # Register the new blueprint

    return app
