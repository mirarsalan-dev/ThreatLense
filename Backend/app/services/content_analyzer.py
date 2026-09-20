from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse

class ContentAnalyzer:
    @staticmethod
    def analyze_html(html_content, target_url):
        """
        Parses the DOM to extract security-relevant indicators.
        """
        results = {
            "forms_found": 0,
            "suspicious_forms": [],
            "iframes_found": 0,
            "hidden_iframes": [],
            "external_resources": 0,
            "title": "",
            "warnings": []
        }
        
        if not html_content:
            return results
            
        try:
            target_domain = urlparse(target_url).hostname
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract Title
            if soup.title:
                results["title"] = soup.title.string
                
            # Analyze Forms
            forms = soup.find_all('form')
            results["forms_found"] = len(forms)
            
            for idx, form in enumerate(forms):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                
                # Check for password inputs
                has_password = len(form.find_all('input', type='password')) > 0
                
                # Check where it posts
                posts_externally = False
                if action.startswith('http'):
                    action_domain = urlparse(action).hostname
                    if action_domain and target_domain and action_domain != target_domain:
                        posts_externally = True
                        
                if has_password or posts_externally:
                    results["suspicious_forms"].append({
                        "form_index": idx,
                        "has_password_field": has_password,
                        "posts_externally": posts_externally,
                        "action": action
                    })
                    
            # Analyze Iframes
            iframes = soup.find_all('iframe')
            results["iframes_found"] = len(iframes)
            
            for iframe in iframes:
                # Check if hidden
                style = iframe.get('style', '').replace(' ', '')
                width = iframe.get('width', '')
                height = iframe.get('height', '')
                is_hidden = False
                
                if 'display:none' in style or 'visibility:hidden' in style:
                    is_hidden = True
                if width in ['0', '1'] or height in ['0', '1']:
                    is_hidden = True
                    
                if is_hidden:
                    results["hidden_iframes"].append(iframe.get('src', 'unknown_src'))
                    results["warnings"].append("Hidden iframe detected.")

            # External Resources (scripts, links, imgs)
            ext_count = 0
            for tag in soup.find_all(['script', 'link', 'img']):
                src = tag.get('src') or tag.get('href')
                if src and src.startswith('http'):
                    src_domain = urlparse(src).hostname
                    if src_domain and target_domain and src_domain != target_domain:
                        ext_count += 1
            results["external_resources"] = ext_count

        except Exception as e:
            results["warnings"].append(f"DOM parsing failed: {str(e)}")
            
        return results
