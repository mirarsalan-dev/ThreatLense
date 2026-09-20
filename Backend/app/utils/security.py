import time
from functools import wraps
from flask import request, jsonify, current_app
from collections import defaultdict

# Simple In-Memory Rate Limiter
_RATE_LIMITS = defaultdict(list)

def rate_limit(limit=10, per=60):
    """
    Rate limit decorator based on IP. 
    Allows `limit` requests per `per` seconds.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            
            # Clean up old timestamps
            _RATE_LIMITS[ip] = [t for t in _RATE_LIMITS[ip] if now - t < per]
            
            if len(_RATE_LIMITS[ip]) >= limit:
                return jsonify({"error": "Rate limit exceeded"}), 429
                
            _RATE_LIMITS[ip].append(now)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def csrf_protect(f):
    """
    Validates Origin/Referer for POST/PUT/DELETE requests to prevent CSRF.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE']:
            origin = request.headers.get('Origin')
            referer = request.headers.get('Referer')
            
            # In a real production app, compare against allowed origins
            # Here we just ensure it's coming from the same host
            host_url = request.host_url.rstrip('/')
            
            if origin and not origin.startswith(host_url):
                return jsonify({"error": "Invalid Origin"}), 403
                
            if referer and not referer.startswith(host_url):
                return jsonify({"error": "Invalid Referer"}), 403
                
        return f(*args, **kwargs)
    return decorated_function

def get_user_role(user_id):
    try:
        from firebase_admin import firestore
        db = firestore.client()
        user_doc = db.collection('users').document(user_id).get()
        if user_doc.exists:
            return user_doc.to_dict().get('role', 'VIEWER')
    except Exception:
        pass
    return 'VIEWER'

def require_role(allowed_roles):
    """
    Validates if the current session user has one of the allowed roles.
    Allowed roles: SUPER_ADMIN, SOC_ANALYST, SECURITY_RESEARCHER, VIEWER
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import session
            from app.services.audit_service import AuditService
            
            user_id = session.get('user_id')
            if not user_id:
                return jsonify({"error": "Unauthorized"}), 401
                
            role = get_user_role(user_id)
            if role not in allowed_roles:
                AuditService.log_security_event(
                    'UNAUTHORIZED_ACCESS', 'HIGH', 'BLOCKED', 
                    reason=f'Role {role} attempted to access restricted endpoint', 
                    resource=request.path
                )
                return jsonify({"error": "Forbidden - Insufficient Role"}), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_permission(permission):
    """
    For more granular resource-level permission checks.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import session
            from app.services.audit_service import AuditService
            
            user_id = session.get('user_id')
            if not user_id:
                return jsonify({"error": "Unauthorized"}), 401
                
            # Basic permission mapping based on roles
            role = get_user_role(user_id)
            
            permissions = {
                'SUPER_ADMIN': ['read_all', 'write_all', 'delete_all', 'admin'],
                'SOC_ANALYST': ['read_all', 'write_all'],
                'SECURITY_RESEARCHER': ['read_all', 'scan_urls'],
                'VIEWER': ['read_all']
            }
            
            user_perms = permissions.get(role, [])
            if permission not in user_perms and 'admin' not in user_perms:
                AuditService.log_security_event(
                    'UNAUTHORIZED_ACCESS', 'HIGH', 'BLOCKED', 
                    reason=f'Role {role} lacks permission {permission}', 
                    resource=request.path
                )
                return jsonify({"error": f"Forbidden - Missing permission {permission}"}), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator
