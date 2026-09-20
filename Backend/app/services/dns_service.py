import dns.resolver
from datetime import datetime

class DNSService:
    @staticmethod
    def query_all(domain):
        """
        Query all critical DNS records for a given domain.
        Returns a dictionary with the results or error status.
        """
        results = {
            "status": "SUCCESS",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "records": {}
        }
        
        # We only want the root domain or subdomains, no schema/paths.
        # This assumes domain string is already sanitized.
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type, lifetime=3.0)
                results["records"][record_type] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                results["records"][record_type] = []
            except dns.resolver.NXDOMAIN:
                results["status"] = "FAILED"
                results["error"] = "NXDOMAIN - Domain does not exist"
                break
            except Exception as e:
                # Could be timeout or other network error
                results["records"][record_type] = []
                results["warnings"] = results.get("warnings", []) + [f"Failed to fetch {record_type}: {str(e)}"]

        # Specifically look for SPF in TXT records
        if "TXT" in results["records"]:
            spf_records = [txt for txt in results["records"]["TXT"] if "v=spf1" in txt]
            results["records"]["SPF"] = spf_records

        return results
