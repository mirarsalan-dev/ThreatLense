import ssl
import socket
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class SSLService:
    @staticmethod
    def get_certificate_info(hostname, port=443, timeout=3.0):
        """
        Connects to the hostname on port 443 and extracts SSL/TLS certificate details.
        """
        results = {
            "status": "SUCCESS",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "details": {}
        }
        
        context = ssl.create_default_context()
        # Don't verify strictly because we WANT to analyze bad/expired certs!
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get binary certificate
                    der_cert = ssock.getpeercert(binary_form=True)
                    if not der_cert:
                        results["status"] = "FAILED"
                        results["error"] = "No certificate presented"
                        return results
                        
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    
                    # Extract details
                    try:
                        issuer = cert.issuer.rfc4514_string()
                    except:
                        issuer = "Unknown"
                        
                    try:
                        subject = cert.subject.rfc4514_string()
                    except:
                        subject = "Unknown"
                        
                    not_valid_before = cert.not_valid_before_utc.isoformat() + "Z"
                    not_valid_after = cert.not_valid_after_utc.isoformat() + "Z"
                    
                    # Check expiration manually
                    is_expired = datetime.utcnow().replace(tzinfo=cert.not_valid_after_utc.tzinfo) > cert.not_valid_after_utc
                    
                    results["details"] = {
                        "issuer": issuer,
                        "subject": subject,
                        "valid_from": not_valid_before,
                        "valid_to": not_valid_after,
                        "is_expired": is_expired,
                        "version": getattr(cert, 'version', 'Unknown').name if hasattr(cert, 'version') else "Unknown"
                    }
                    
                    # Extract SANs if present
                    try:
                        ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        sans = ext.value.get_values_for_type(x509.DNSName)
                        results["details"]["san"] = sans
                    except x509.ExtensionNotFound:
                        results["details"]["san"] = []
                        
        except socket.timeout:
            results["status"] = "TIMEOUT"
            results["error"] = f"Connection to {hostname}:{port} timed out."
        except socket.gaierror:
            results["status"] = "FAILED"
            results["error"] = "DNS resolution failed."
        except Exception as e:
            results["status"] = "FAILED"
            results["error"] = str(e)
            
        return results
