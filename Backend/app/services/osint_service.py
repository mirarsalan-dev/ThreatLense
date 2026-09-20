import concurrent.futures
from urllib.parse import urlparse
from app.services.dns_service import DNSService
from app.services.ssl_service import SSLService
from app.services.whois_service import WhoisService
from app.services.reputation_service import ReputationService
from datetime import datetime

class OSINTService:
    @staticmethod
    def extract_domain(url):
        """
        Extracts the hostname/domain from a URL safely.
        """
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        parsed = urlparse(url)
        return parsed.hostname

    @staticmethod
    def gather_intelligence(url):
        """
        Orchestrates concurrent intelligence gathering modules.
        Returns a unified OSINT report dictionary.
        """
        hostname = OSINTService.extract_domain(url)
        
        if not hostname:
            return {
                "status": "FAILED",
                "error": "Could not extract valid hostname from URL",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }

        report = {
            "target_domain": hostname,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "modules": {}
        }

        # Run modules concurrently to minimize wait time
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            future_dns = executor.submit(DNSService.query_all, hostname)
            future_ssl = executor.submit(SSLService.get_certificate_info, hostname)
            future_whois = executor.submit(WhoisService.get_whois_data, hostname)
            future_rep = executor.submit(ReputationService.get_reputation, hostname)
            
            try:
                report["modules"]["dns"] = future_dns.result(timeout=5.0)
            except concurrent.futures.TimeoutError:
                report["modules"]["dns"] = {"status": "TIMEOUT", "error": "DNS query timed out"}
            except Exception as e:
                report["modules"]["dns"] = {"status": "FAILED", "error": str(e)}
                
            try:
                report["modules"]["ssl"] = future_ssl.result(timeout=5.0)
            except concurrent.futures.TimeoutError:
                report["modules"]["ssl"] = {"status": "TIMEOUT", "error": "SSL query timed out"}
            except Exception as e:
                report["modules"]["ssl"] = {"status": "FAILED", "error": str(e)}
                
            try:
                report["modules"]["whois"] = future_whois.result(timeout=10.0)
            except concurrent.futures.TimeoutError:
                report["modules"]["whois"] = {"status": "TIMEOUT", "error": "WHOIS query timed out"}
            except Exception as e:
                report["modules"]["whois"] = {"status": "FAILED", "error": str(e)}

            try:
                report["modules"]["reputation"] = future_rep.result(timeout=5.0)
            except concurrent.futures.TimeoutError:
                report["modules"]["reputation"] = {"status": "TIMEOUT", "error": "Reputation query timed out"}
            except Exception as e:
                report["modules"]["reputation"] = {"status": "FAILED", "error": str(e)}

        return report
