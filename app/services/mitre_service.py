class MitreService:
    @staticmethod
    def map_scan(scan_data):
        """
        Maps a scan's ML features and content analysis to MITRE ATT&CK TTPs.
        Returns a structured dictionary matching the MITRE UI.
        """
        ttps = {
            "initial_access": [],
            "execution": [],
            "defense_evasion": [],
            "credential_access": []
        }
        
        ml_features = scan_data.get("ml_analysis", {}).get("features", {})
        verdict = scan_data.get("ml_analysis", {}).get("prediction")
        
        # Initial Access (TA0001)
        if verdict == "phishing":
            ttps["initial_access"].append({
                "id": "T1566",
                "name": "Phishing",
                "evidence": "Detected via URL structure & OSINT",
                "confidence": "High",
                "active": True
            })
        else:
            ttps["initial_access"].append({
                "id": "T1566",
                "name": "Phishing",
                "active": False
            })
            
        ttps["initial_access"].append({"id": "T1190", "name": "Exploit Public-Facing App", "active": False})
        ttps["initial_access"].append({"id": "T1078", "name": "Valid Accounts", "active": False})

        # Execution (TA0002)
        if ml_features.get("suspicious_words", 0) > 0 or ml_features.get("is_obfuscated", False):
            ttps["execution"].append({
                "id": "T1059.007",
                "name": "JavaScript",
                "evidence": "Suspicious keywords or obfuscation detected",
                "confidence": "Medium",
                "active": True
            })
        else:
            ttps["execution"].append({
                "id": "T1059.007",
                "name": "JavaScript",
                "active": False
            })
            
        ttps["execution"].append({"id": "T1204", "name": "User Execution", "active": False})
        ttps["execution"].append({"id": "T1047", "name": "Windows Management Instrumentation", "active": False})

        # Defense Evasion (TA0005)
        if ml_features.get("url_entropy", 0) > 4.5 or ml_features.get("is_obfuscated", False):
            ttps["defense_evasion"].append({
                "id": "T1027",
                "name": "Obfuscated Files or Information",
                "evidence": "High entropy or obfuscated URL pattern",
                "confidence": "High",
                "active": True
            })
        else:
            ttps["defense_evasion"].append({
                "id": "T1027",
                "name": "Obfuscated Files or Information",
                "active": False
            })
            
        ttps["defense_evasion"].append({"id": "T1562", "name": "Impair Defenses", "active": False})

        # Credential Access (TA0006)
        if ml_features.get("has_login_form", False) or verdict == "phishing":
            ttps["credential_access"].append({
                "id": "T1056",
                "name": "Input Capture",
                "evidence": "Suspicious credential collection endpoint",
                "confidence": "High",
                "active": True
            })
        else:
            ttps["credential_access"].append({
                "id": "T1056",
                "name": "Input Capture",
                "active": False
            })
            
        ttps["credential_access"].append({"id": "T1110", "name": "Brute Force", "active": False})
        ttps["credential_access"].append({"id": "T1552", "name": "Unsecured Credentials", "active": False})

        return ttps
