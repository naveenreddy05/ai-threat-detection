# Path: src/api/security.py
import os
import secrets
import hashlib
import logging
from functools import wraps
from flask import request, jsonify

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Default API key for development
DEFAULT_API_KEY = "dev_hackathon_key"

# Environment variable to store API key
API_KEY_ENV_VAR = "AI_THREAT_DETECTION_API_KEY"

def get_api_key():
    """Get the API key from environment or use default for development."""
    return os.environ.get(API_KEY_ENV_VAR, DEFAULT_API_KEY)

def generate_api_key():
    """Generate a secure API key."""
    return secrets.token_hex(32)

def hash_api_key(api_key):
    """Hash an API key for secure storage."""
    return hashlib.sha256(api_key.encode()).hexdigest()

def require_api_key(f):
    """Decorator to require API key for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        # Skip API key check in development mode
        if os.environ.get('FLASK_ENV') == 'development' and not api_key:
            return f(*args, **kwargs)
        
        if not api_key:
            logger.warning("API request without API key")
            return jsonify({
                'success': False,
                'error': "API key is required"
            }), 401
        
        expected_key = get_api_key()
        if api_key != expected_key:
            logger.warning(f"Invalid API key used: {api_key[:10]}...")
            return jsonify({
                'success': False,
                'error': "Invalid API key"
            }), 401
            
        return f(*args, **kwargs)
    return decorated_function

# To apply the decorator to routes in routes.py:
# @app.route('/api/protected-endpoint')
# @require_api_key
# def protected_endpoint():
#     ...
