from flask import Blueprint, jsonify, request
import time
from app.services.url_analyzer import URLAnalyzerService
from app.services.osint_service import OSINTService
from app.services.forensics_service import ForensicsService

scanner_bp = Blueprint('scanner', __name__)
url_analyzer = URLAnalyzerService()

@scanner_bp.route('/scan', methods=['POST'])
def scan_url():
    data = request.json
    url = data.get('url')
    case_id = data.get('case_id')
    
    if not url:
        return jsonify({"error": "URL is required"}), 400

    # Execute analysis
    try:
        analysis_result = url_analyzer.analyze_url(url)
        
        # Calculate risk score (0-100)
        # Using confidence for now if phishing, or low score if safe
        ml = analysis_result["ml_analysis"]
        if ml["prediction"] == "phishing":
            risk_score = int(ml["confidence"] * 100)
        else:
            risk_score = int((1 - ml["confidence"]) * 100) if ml["confidence"] > 0.5 else int(ml["confidence"] * 100)

        osint_report = OSINTService.gather_intelligence(url)
        forensics_report = ForensicsService.gather_forensics(url)

        response = {
            "scan_id": f"scan_{int(time.time())}",
            "case_id": case_id,
            "url": url,
            "status": "completed",
            "verdict": ml["prediction"],
            "risk_score": risk_score,
            "ml_analysis": ml,
            "osint": osint_report,
            "forensics": forensics_report,
            "features_extracted": len(analysis_result["features"])
        }

        from app.services.db_service import DBService
        
        # Save the main scan
        DBService.save_scan(response)

        # Record timeline events if this is part of a case
        if case_id:
            DBService.record_timeline_event(case_id, "TARGET_RECEIVED", f"Target {url} accepted for full autopsy.", "USER")
            DBService.record_timeline_event(case_id, "ML_ANALYSIS", f"ML Engine predicted {ml['prediction'].upper()} with {risk_score}% confidence based on {len(analysis_result['features'])} features.", "ML_ENGINE")
            
            osint_found = len(osint_report) > 0
            DBService.record_timeline_event(case_id, "OSINT_GATHERED", f"OSINT Engine completed external intelligence correlation. Data found: {osint_found}", "OSINT_ENGINE")
            
            DBService.record_timeline_event(case_id, "WEB_FORENSICS", f"Web forensics completed. DOM/JS analyzed successfully.", "FORENSICS_ENGINE")
            DBService.record_timeline_event(case_id, "INVESTIGATION_COMPLETED", f"Deep autopsy completed. Evidence and DNA archived.", "SYSTEM")

        return jsonify(response)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
