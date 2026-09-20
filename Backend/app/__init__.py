import os
from flask import Flask, request
import firebase_admin
from firebase_admin import credentials

def create_app():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    frontend_dir = os.path.abspath(os.path.join(base_dir, '..', '..', 'Frontend'))
    
    template_dir = os.path.join(frontend_dir, 'templates')
    static_dir = os.path.join(frontend_dir, 'static')
    
    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    app.config.from_object('config.Config')

    # Initialize Firebase Admin SDK
    cred_path = app.config.get('FIREBASE_CREDENTIALS_PATH')
    if cred_path and os.path.exists(cred_path):
        try:
            cred = credentials.Certificate(cred_path)
            firebase_admin.initialize_app(cred)
            print("Firebase initialized successfully.")
        except Exception as e:
            print(f"Error initializing Firebase: {e}")
    else:
        print("Warning: Firebase credentials not found. Some features may be disabled.")

    # Register blueprints
    from .routes.auth import auth_bp
    from .routes.dashboard import dashboard_bp
    from .routes.scanner import scanner_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scanner_bp, url_prefix='/api')

    # Secure Cookies Config
    app.config['SESSION_COOKIE_NAME'] = 'threatlense_session'
    app.config['SESSION_COOKIE_SECURE'] = False # Must be False for local HTTP dev
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    @app.before_request
    def run_self_defense():
        from app.security.self_defense import SelfDefenseEngine
        # Exempt static files from inspection to save resources
        if request.path.startswith('/static/'):
            return None
        return SelfDefenseEngine.inspect_request()

    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com https://www.gstatic.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https://cdn.jsdelivr.net; "
            "connect-src 'self' https://cdn.jsdelivr.net https://unpkg.com https://identitytoolkit.googleapis.com https://securetoken.googleapis.com;"
        )
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response

    return app
