import re
from bs4 import BeautifulSoup

class JSAnalyzer:
    @staticmethod
    def analyze_javascript(html_content):
        """
        Performs static analysis on embedded JavaScript blocks.
        Never executes the JS.
        """
        results = {
            "inline_scripts_count": 0,
            "eval_count": 0,
            "suspicious_functions": [],
            "obfuscation_detected": False,
            "warnings": []
        }
        
        if not html_content:
            return results
            
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            scripts = soup.find_all('script')
            
            inline_scripts = [s.string for s in scripts if s.string]
            results["inline_scripts_count"] = len(inline_scripts)
            
            suspicious_patterns = [
                (r'unescape\(', 'unescape() call detected'),
                (r'document\.write\(', 'document.write() call detected'),
                (r'String\.fromCharCode\(', 'String.fromCharCode() usage'),
                (r'setTimeout\([^,]+,', 'Obfuscated setTimeout detected')
            ]
            
            for js_code in inline_scripts:
                # Count evals
                results["eval_count"] += len(re.findall(r'\beval\s*\(', js_code))
                
                # Check for suspicious patterns
                for pattern, desc in suspicious_patterns:
                    if re.search(pattern, js_code) and desc not in results["suspicious_functions"]:
                        results["suspicious_functions"].append(desc)
                        
                # Simple heuristic for obfuscation: high density of hex/unicode escapes or extremely long contiguous strings without spaces
                hex_escapes = len(re.findall(r'\\x[0-9a-fA-F]{2}', js_code))
                unicode_escapes = len(re.findall(r'\\u[0-9a-fA-F]{4}', js_code))
                
                if (hex_escapes + unicode_escapes) > 20:
                    results["obfuscation_detected"] = True
                    if "High density of escaped characters" not in results["warnings"]:
                        results["warnings"].append("High density of escaped characters (potential obfuscation).")

        except Exception as e:
            results["warnings"].append(f"JS parsing failed: {str(e)}")
            
        return results
