class GraphService:
    @staticmethod
    def build_graph(scan_data):
        """
        Extracts entities from scan data and constructs a nodes/edges graph
        for visualization in Vis.js.
        """
        nodes = []
        edges = []
        node_id_map = {}
        
        def get_node_id(label, group):
            if label not in node_id_map:
                node_id_map[label] = {
                    "id": len(node_id_map) + 1,
                    "label": label,
                    "group": group,
                    "value": 15
                }
                nodes.append(node_id_map[label])
            return node_id_map[label]["id"]
            
        url = scan_data.get("url", "unknown_url")
        url_id = get_node_id(url, "domain")
        
        # Make the central node larger if malicious
        if scan_data.get("ml_analysis", {}).get("prediction") == "phishing":
            node_id_map[url]["value"] = 25
            
        osint = scan_data.get("osint", {})
        
        # Domain
        domain = osint.get("target_domain")
        if domain and domain != url:
            dom_id = get_node_id(domain, "domain")
            edges.append({"from": url_id, "to": dom_id, "label": "Parsed To"})
            url_id = dom_id # Make domain the hub for IP/DNS
            
        # DNS A Records -> IPs
        modules = osint.get("modules", {})
        dns = modules.get("dns", {})
        a_records = dns.get("A", [])
        if isinstance(a_records, list):
            for ip in a_records:
                ip_id = get_node_id(ip, "ip")
                edges.append({"from": url_id, "to": ip_id, "label": "A Record"})
                
        # ASN / WHOIS info (Mocking extraction from WHOIS string or IP lookup)
        # If we had a real ASN lookup, we'd add it here.
        whois = modules.get("whois", {})
        registrar = whois.get("registrar")
        if registrar:
            reg_id = get_node_id(f"Registrar: {registrar}", "asn")
            edges.append({"from": url_id, "to": reg_id, "label": "Registered With"})
            
        # If no edges were formed (maybe no OSINT), add some generic placeholders based on ML features
        if len(edges) == 0:
            if scan_data.get("ml_analysis", {}).get("features", {}).get("is_https", False):
                ssl_id = get_node_id("HTTPS Port 443", "asn")
                edges.append({"from": url_id, "to": ssl_id, "label": "Listens On"})
                
        return {"nodes": nodes, "edges": edges}
