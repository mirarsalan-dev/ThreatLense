import time
import re
from flask import request, jsonify
from collections import defaultdict
from app.services.audit_service import AuditService

class ThreatDetector:
    # Common attack signatures
    SQLI_PATTERN = re.compile(r'(?i)(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|--\s*$)')
    XSS_PATTERN = re.compile(r'(?i)(<script>|javascript:|onerror=|onload=)')
    TRAVERSAL_PATTERN = re.compile(r'(\.\./|\.\.\\)')
    CMD_INJECTION_PATTERN = re.compile(r'(?i)(;\s*ls\s|\|\s*cat\s|`.*`)')

    @classmethod
    def analyze_payload(cls, payload):
        if not payload:
            return None
        
        payload_str = str(payload)
        
        if cls.SQLI_PATTERN.search(payload_str):
            return "SQL Injection"
        if cls.XSS_PATTERN.search(payload_str):
            return "Cross-Site Scripting (XSS)"
        if cls.TRAVERSAL_PATTERN.search(payload_str):
            return "Path Traversal"
        if cls.CMD_INJECTION_PATTERN.search(payload_str):
            return "Command Injection"
            
        return None

class AdaptiveRateLimiter:
    # In-memory store for demonstration (in production, use Redis)
    _VIOLATIONS = defaultdict(int)
    _BANS = {}
    _REQUESTS = defaultdict(list)

    @classmethod
    def check_request(cls, ip, max_requests=60, window_sec=60):
        now = time.time()
        
        # Check if banned
        if ip in cls._BANS:
            if now < cls._BANS[ip]:
                return False, "Temporarily banned due to excessive violations"
            else:
                del cls._BANS[ip]
                
        # Clean old requests
        cls._REQUESTS[ip] = [t for t in cls._REQUESTS[ip] if now - t < window_sec]
        
        # Current limit depends on previous violations
        current_limit = max(10, max_requests - (cls._VIOLATIONS[ip] * 10))
        
        if len(cls._REQUESTS[ip]) >= current_limit:
            cls._VIOLATIONS[ip] += 1
            
            # If 3 violations, ban for 5 minutes
            if cls._VIOLATIONS[ip] >= 3:
                cls._BANS[ip] = now + 300
                AuditService.log_security_event('RATE_LIMIT_TRIGGERED', 'HIGH', 'RESTRICTED', reason='Adaptive ban applied', resource=ip)
                return False, "Adaptive rate limit exceeded. IP banned."
            else:
                AuditService.log_security_event('RATE_LIMIT_TRIGGERED', 'MEDIUM', 'BLOCKED', reason='Rate limit exceeded', resource=ip)
                return False, "Rate limit exceeded."
                
        cls._REQUESTS[ip].append(now)
        return True, ""

class SelfDefenseEngine:
    @staticmethod
    def inspect_request():
        """
        To be called in before_request.
        """
        ip = request.remote_addr
        
        # 1. Rate Limiting
        allowed, msg = AdaptiveRateLimiter.check_request(ip)
        if not allowed:
            return jsonify({"error": msg, "threat_prevented": True}), 429
            
        # 2. Payload Inspection
        payload = None
        if request.is_json:
            payload = request.json
        elif request.form:
            payload = request.form
        elif request.args:
            payload = request.args
            
        threat_type = ThreatDetector.analyze_payload(payload)
        
        if threat_type:
            AuditService.log_security_event(
                'MALICIOUS_PAYLOAD_DETECTED', 'CRITICAL', 'BLOCKED', 
                reason=f'{threat_type} detected in request', 
                resource=request.path
            )
            # Penalize the IP
            AdaptiveRateLimiter._VIOLATIONS[ip] += 1
            return jsonify({"error": "Malicious payload detected and blocked.", "threat_prevented": True}), 403
            
        return None
