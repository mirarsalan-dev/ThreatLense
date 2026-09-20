import datetime
import uuid
from flask import request, session
from firebase_admin import firestore

class AuditService:
    @staticmethod
    def log_security_event(event_type, severity, action, reason=None, resource=None, metadata=None):
        """
        Logs a normalized security event to the 'security_events' Firestore collection.
        
        Args:
            event_type (str): E.g., 'LOGIN_SUCCESS', 'SSRF_BLOCKED', 'RATE_LIMIT'
            severity (str): 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
            action (str): The action taken (e.g., 'ALLOWED', 'BLOCKED', 'RESTRICTED')
            reason (str, optional): The reason for the action.
            resource (str, optional): The resource being accessed (URL path, case ID, etc).
            metadata (dict, optional): Any additional safe context. DO NOT LOG SECRETS.
        """
        try:
            db = firestore.client()
            events_ref = db.collection('security_events')
            
            # Sanitize metadata to prevent secret leakage
            safe_metadata = metadata or {}
            for sensitive_key in ['password', 'token', 'secret', 'key']:
                if sensitive_key in safe_metadata:
                    safe_metadata[sensitive_key] = '[REDACTED]'
            
            # Use request objects safely in case of background workers
            source_ip = "system"
            user_agent = "system"
            request_path = "system"
            actor = "system"
            
            try:
                from flask import request, session
                if request:
                    source_ip = request.remote_addr
                    user_agent = request.user_agent.string
                    request_path = request.path
                if session:
                    actor = session.get('user_id', 'anonymous')
            except RuntimeError:
                pass # Working outside application context
            
            event_data = {
                "event_id": str(uuid.uuid4()),
                "event_type": event_type,
                "severity": severity,
                "timestamp": firestore.SERVER_TIMESTAMP,
                "actor": actor,
                "source_ip": source_ip,
                "user_agent": user_agent,
                "request_path": request_path,
                "action": action,
                "reason": reason,
                "resource": resource,
                "metadata": safe_metadata
            }
            
            events_ref.add(event_data)
        except Exception as e:
            # Fallback to standard logging if DB is unreachable
            print(f"CRITICAL: Failed to write audit log to DB: {e}")
            print(f"FAILED LOG EVENT: {event_type} - {action} - {reason}")
