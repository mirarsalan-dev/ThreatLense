import whois
from datetime import datetime

class WhoisService:
    @staticmethod
    def get_whois_data(domain):
        """
        Extracts WHOIS registration details for a domain.
        """
        results = {
            "status": "SUCCESS",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "details": {}
        }
        
        try:
            # Query whois
            w = whois.whois(domain)
            
            # Helper to extract first item if list
            def extract_first(value):
                if isinstance(value, list):
                    return value[0]
                return value
                
            creation_date = extract_first(w.creation_date)
            expiration_date = extract_first(w.expiration_date)
            
            domain_age_days = None
            if isinstance(creation_date, datetime):
                domain_age_days = (datetime.now() - creation_date).days
                
            results["details"] = {
                "registrar": extract_first(w.registrar),
                "creation_date": creation_date.isoformat() + "Z" if isinstance(creation_date, datetime) else str(creation_date),
                "expiration_date": expiration_date.isoformat() + "Z" if isinstance(expiration_date, datetime) else str(expiration_date),
                "domain_age_days": domain_age_days,
                "emails": w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else [],
                "org": extract_first(w.org),
                "country": extract_first(w.country)
            }
            
        except Exception as e:
            results["status"] = "FAILED"
            results["error"] = str(e)
            
        return results
