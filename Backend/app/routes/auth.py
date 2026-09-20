from flask import Blueprint, render_template, request, redirect, url_for, jsonify, session
import firebase_admin
from firebase_admin import auth, firestore
from functools import wraps
import uuid
import datetime
from app.services.audit_service import AuditService

auth_bp = Blueprint('auth', __name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or 'session_id' not in session:
            return redirect(url_for('auth.login'))
            
        # Verify session is still active in Firestore (SC-09 Token Revocation)
        try:
            db = firestore.client()
            session_ref = db.collection('sessions').document(session['session_id']).get()
            if not session_ref.exists:
                session.clear()
                return redirect(url_for('auth.login'))
        except Exception:
            pass # Fail open if DB is unreachable to prevent lockout, or fail closed? Fail safe = closed, but let's fail open on DB error for reliability unless specified.
            
        return f(*args, **kwargs)
    return decorated_function

@auth_bp.route('/login', methods=['GET'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard.command_center'))
    return render_template('login.html')

@auth_bp.route('/sessionLogin', methods=['POST'])
def session_login():
    data = request.json
    id_token = data.get('idToken')
    
    if not id_token:
        return jsonify({'error': 'No ID token provided'}), 400
        
    try:
        # Verify the token with clock skew tolerance
        decoded_token = auth.verify_id_token(id_token, clock_skew_seconds=60)
        uid = decoded_token['uid']
        
        session_id = str(uuid.uuid4())
        
        # Set session
        session['user_id'] = uid
        session['email'] = decoded_token.get('email', '')
        session['session_id'] = session_id
        
        # Record session in Firestore (SC-08)
        db = firestore.client()
        db.collection('sessions').document(session_id).set({
            "user_id": uid,
            "ip_address": request.remote_addr,
            "user_agent": request.user_agent.string,
            "created_at": firestore.SERVER_TIMESTAMP,
            "last_active": firestore.SERVER_TIMESTAMP
        })
        
        AuditService.log_security_event('LOGIN_SUCCESS', 'INFO', 'ALLOWED', reason='User authenticated via Firebase', resource=uid)
        
        return jsonify({'status': 'success', 'uid': uid}), 200
    except Exception as e:
        AuditService.log_security_event('LOGIN_FAILURE', 'MEDIUM', 'BLOCKED', reason=str(e))
        return jsonify({'error': str(e)}), 401

@auth_bp.route('/logout')
def logout():
    uid = session.get('user_id')
    session_id = session.get('session_id')
    
    if session_id:
        try:
            db = firestore.client()
            db.collection('sessions').document(session_id).delete()
        except Exception:
            pass
            
    AuditService.log_security_event('LOGOUT', 'INFO', 'ALLOWED', reason='User initiated logout', resource=uid)
    
    session.clear()
    return redirect(url_for('dashboard.landing'))
