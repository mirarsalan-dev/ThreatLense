import requests
from datetime import datetime
from app.services.content_analyzer import ContentAnalyzer
from app.services.js_analyzer import JSAnalyzer

class ForensicsService:
    @staticmethod
    def gather_forensics(url):
        """
        Safely downloads the target HTML (with strict limits) and runs static analysis.
        """
        report = {
            "status": "SUCCESS",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "http_status": None,
            "server_headers": {},
            "html_analysis": {},
            "js_analysis": {}
        }

        # Format URL properly
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.scheme not in ['http', 'https']:
            raise ValueError(f"Invalid URL scheme: {parsed.scheme}")

        try:
            import socket, ipaddress
            from urllib.parse import urlparse
            
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                raise ValueError("Invalid URL hostname")
                
            ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                raise ValueError("SSRF BLOCKED: Attempted to access private/internal IP.")

            # STRICT SECURITY LIMITS
            # 5-second timeout, do not follow infinite redirects, emulate standard browser user-agent
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.get(
                url, 
                headers=headers, 
                timeout=5.0,
                allow_redirects=True,
                stream=True # Use stream to prevent downloading massive files
            )
            
            report["http_status"] = response.status_code
            
            # Safely capture security headers (CSP, X-Frame-Options)
            useful_headers = ['Server', 'X-Powered-By', 'Content-Security-Policy', 'X-Frame-Options']
            for h in useful_headers:
                if h in response.headers:
                    report["server_headers"][h] = response.headers[h]
            
            # Read first 2MB only to prevent memory exhaustion / Zip bombs
            max_bytes = 2 * 1024 * 1024
            content = response.raw.read(max_bytes, decode_content=True)
            html_content = content.decode('utf-8', errors='ignore')
            
            if response.raw.read(1):
                report["html_analysis"]["warnings"] = ["Payload truncated (exceeded 2MB limit)."]

            # Run Analysis
            report["html_analysis"].update(ContentAnalyzer.analyze_html(html_content, url))
            report["js_analysis"].update(JSAnalyzer.analyze_javascript(html_content))

        except requests.exceptions.Timeout:
            report["status"] = "TIMEOUT"
            report["error"] = "Connection to target timed out after 5 seconds."
        except requests.exceptions.TooManyRedirects:
            report["status"] = "FAILED"
            report["error"] = "Too many redirects detected."
        except requests.exceptions.RequestException as e:
            report["status"] = "FAILED"
            report["error"] = f"Network error: {str(e)}"
        except Exception as e:
            report["status"] = "FAILED"
            report["error"] = f"Forensics engine error: {str(e)}"

        return report
