from datetime import datetime

class ReputationService:
    @staticmethod
    def get_reputation(domain):
        """
        Simulates checking a domain against reputation engines like VirusTotal.
        In a production environment, this would call the VirusTotal API using an API key.
        """
        results = {
            "status": "SUCCESS",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "details": {
                "virustotal_score": "SIMULATION: 0/94",
                "google_safe_browsing": "CLEAN",
                "spamhaus": "CLEAN"
            }
        }
        
        # Simple simulated logic based on common suspicious keywords
        suspicious_keywords = ['login', 'secure', 'account', 'verify', 'update', 'banking', 'free']
        if any(keyword in domain.lower() for keyword in suspicious_keywords):
            results["details"]["virustotal_score"] = "SIMULATION: 3/94 (SUSPICIOUS)"
            
        return results
