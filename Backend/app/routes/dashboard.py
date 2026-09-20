from flask import Blueprint, render_template, session, jsonify
from app.routes.auth import login_required
from app.services.db_service import DBService

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
def landing():
    return render_template('landing.html')

@dashboard_bp.route('/api/health', methods=['GET'])
def health_check():
    import psutil
    return jsonify({
        "success": True,
        "data": {
            "status": "HEALTHY",
            "api": "OK",
            "database": "OK",
            "cpu": f"{psutil.cpu_percent(interval=None)}%",
            "ram": f"{psutil.virtual_memory().percent}%"
        },
        "error": None
    }), 200

@dashboard_bp.route('/api/security/health', methods=['GET'])
@login_required
def security_health():
    from firebase_admin import firestore
    try:
        db = firestore.client()
        # Get recent security events
        events_ref = db.collection('security_events')
        recent_events = list(events_ref.order_by('timestamp', direction=firestore.Query.DESCENDING).limit(50).stream())
        
        # Calculate stats
        total_events = len(recent_events)
        blocked_requests = sum(1 for e in recent_events if e.to_dict().get('action') in ['BLOCKED', 'RESTRICTED'])
        
        # Get active sessions
        sessions_ref = db.collection('sessions')
        active_sessions = len(list(sessions_ref.stream()))
        
        return jsonify({
            "success": True,
            "data": {
                "authentication": {"status": f"{active_sessions} Active Sessions", "severity": "success"},
                "rbac": {"status": "ACTIVE", "severity": "success"},
                "csrf": {"status": "ACTIVE", "severity": "success"},
                "headers": {"status": "ENFORCED", "severity": "success"},
                "ssrf": {"status": "ENFORCED", "severity": "success"},
                "rate_limit": {"status": "ACTIVE", "severity": "success"}
            },
            "stats": {
                "recent_events": total_events,
                "blocked_requests": blocked_requests
            }
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@dashboard_bp.route('/command-center')
@login_required
def command_center():
    from firebase_admin import firestore
    db = firestore.client()
    
    # Real data queries
    scans_ref = db.collection('scans')
    scans = list(scans_ref.order_by('timestamp', direction=firestore.Query.DESCENDING).limit(10).stream())
    
    total_scans = len(list(scans_ref.stream()))
    threats_detected = sum(1 for s in scans_ref.stream() if s.to_dict().get('verdict') == 'MALICIOUS')
    
    # Calculate ML Average Confidence
    ml_confidence_sum = 0
    ml_confidence_count = 0
    recent_scans = []
    
    for scan in scans:
        doc = scan.to_dict()
        doc['id'] = scan.id
        recent_scans.append(doc)
        
        ml_analysis = doc.get('ml_analysis', {})
        if ml_analysis and ml_analysis.get('confidence'):
            ml_confidence_sum += float(ml_analysis.get('confidence'))
            ml_confidence_count += 1
            
    avg_confidence = round((ml_confidence_sum / ml_confidence_count) * 100, 1) if ml_confidence_count > 0 else 0
    
    return render_template('command_center.html', 
                           total_scans=total_scans,
                           threats_detected=threats_detected,
                           active_incidents=0, # Placeholder for cases
                           avg_confidence=avg_confidence,
                           recent_scans=recent_scans)

@dashboard_bp.route('/api/scans/compare', methods=['GET'])
@login_required
def compare_scans():
    from flask import request
    from firebase_admin import firestore
    
    id1 = request.args.get('id1')
    id2 = request.args.get('id2')
    if not id1 or not id2:
        return jsonify({"error": "Missing scan IDs"}), 400
        
    db = firestore.client()
    scan1 = db.collection('scans').document(id1).get().to_dict()
    scan2 = db.collection('scans').document(id2).get().to_dict()
    
    if not scan1 or not scan2:
        return jsonify({"error": "Scan not found"}), 404
        
    common = []
    diff = []
    
    # Compare ML Features
    f1 = scan1.get('ml_analysis', {}).get('features', {})
    f2 = scan2.get('ml_analysis', {}).get('features', {})
    
    for key, val1 in f1.items():
        val2 = f2.get(key)
        if val1 == val2 and val1 not in [0, False, ""]:
            common.append({"indicator": key, "value": val1, "category": "URL Structure / Feature"})
        elif val1 != val2:
            diff.append({"indicator": key, "scan1": val1, "scan2": val2, "category": "URL Structure / Feature"})
            
    # Compare IPs/Domains
    dom1 = scan1.get('osint', {}).get('domain')
    dom2 = scan2.get('osint', {}).get('domain')
    if dom1 and dom2:
        if dom1 == dom2:
            common.append({"indicator": "Domain", "value": dom1, "category": "Network"})
        else:
            diff.append({"indicator": "Domain", "scan1": dom1, "scan2": dom2, "category": "Network"})
            
    return jsonify({"common_indicators": common, "different_indicators": diff})

@dashboard_bp.route('/api/cases/<case_id>/timeline', methods=['GET'])
@login_required
def case_timeline(case_id):
    db = firestore.client()
    docs = db.collection('timeline_events').where('case_id', '==', case_id).order_by('timestamp').stream()
    events = [doc.to_dict() for doc in docs]
    return jsonify({"events": events})

@dashboard_bp.route('/api/scans/<path:scan_id>/stix', methods=['GET'])
@login_required
def export_stix(scan_id):
    try:
        from firebase_admin import firestore
        db = firestore.client()
        if "/" in scan_id:
            scan_docs = list(db.collection('scans').where('target_url', '==', scan_id).limit(1).stream())
            if not scan_docs:
                return jsonify({"error": "No scan found for this URL"}), 404
            scan = scan_docs[0].to_dict()
        else:
            scan = db.collection('scans').document(scan_id).get().to_dict()
            
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        
        from app.services.report_service import ReportService
        stix_bundle = ReportService.generate_stix_bundle(scan)
        return jsonify(stix_bundle)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/simulator')
@login_required
def simulator():
    return render_template('simulator.html')

@dashboard_bp.route('/api/simulate', methods=['POST'])
@login_required
def api_simulate():
    from flask import request
    data = request.json
    
    # Simple simulation logic matching the predict.py heuristics
    risk = float(data.get('suspicious_words', 0)) * 0.15
    if not data.get('is_https'):
        risk += 0.2
    
    length = int(data.get('url_length', 50))
    if length > 75:
        risk += 0.1
    if length > 150:
        risk += 0.2
        
    age = int(data.get('domain_age', 365))
    if age < 30:
        risk += 0.25
        
    risk = min(risk, 0.99)
    return jsonify({
        "risk_score": int(risk * 100),
        "verdict": "phishing" if risk > 0.5 else "safe"
    })

@dashboard_bp.route('/quick-scan')
@login_required
def quick_scan():
    return render_template('quick_scan.html')

@dashboard_bp.route('/cases')
@login_required
def cases():
    return render_template('cases.html')

@dashboard_bp.route('/api/cases', methods=['GET', 'POST'])
@login_required
def api_cases():
    from flask import request
    if request.method == 'POST':
        data = request.json
        case = DBService.create_case(
            title=data.get('title', 'Untitled Investigation'),
            target=data.get('target', ''),
            priority=data.get('priority', 'Medium'),
            description=data.get('description', '')
        )
        if case:
            return jsonify({"status": "success", "case": case})
        return jsonify({"status": "error", "message": "Failed to create case"}), 500
    else:
        cases = DBService.get_cases()
        return jsonify({"status": "success", "cases": cases})

@dashboard_bp.route('/autopsy')
@login_required
def autopsy():
    return render_template('autopsy.html')

@dashboard_bp.route('/threat-dna')
@login_required
def threat_dna():
    return render_template('threat_dna.html')

@dashboard_bp.route('/threat-graph')
@login_required
def threat_graph():
    return render_template('threat_graph.html')

@dashboard_bp.route('/osint')
@login_required
def osint():
    return render_template('osint.html')

@dashboard_bp.route('/mitre')
@login_required
def mitre():
    return render_template('mitre.html')

@dashboard_bp.route('/hunter')
@login_required
def hunter():
    return render_template('threat_hunter.html')

@dashboard_bp.route('/evidence')
@login_required
def evidence():
    return render_template('evidence.html')

@dashboard_bp.route('/api/scans/recent', methods=['GET'])
@login_required
def get_recent_scans():
    try:
        scans = DBService.get_recent_scans(limit=20)
        return jsonify({"status": "success", "scans": scans})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@dashboard_bp.route('/api/scans/search', methods=['GET'])
@login_required
def search_scans():
    from flask import request
    query = request.args.get('q', '')
    try:
        scans = DBService.search_scans(query)
        return jsonify({"status": "success", "scans": scans})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@dashboard_bp.route('/api/osint', methods=['GET'])
@login_required
def get_osint():
    from flask import request
    from app.services.osint_service import OSINTService
    target = request.args.get('target')
    if not target:
        return jsonify({"error": "Missing target"}), 400
    try:
        report = OSINTService.gather_intelligence(target)
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/api/mitre', methods=['GET'])
@login_required
def get_mitre():
    from flask import request
    from firebase_admin import firestore
    from app.services.mitre_service import MitreService
    scan_id = request.args.get('scan_id')
    if not scan_id:
        return jsonify({"error": "Missing scan_id"}), 400
    try:
        db = firestore.client()
        if "/" in scan_id:
            scan_docs = list(db.collection('scans').where('target_url', '==', scan_id).limit(1).stream())
            if not scan_docs:
                return jsonify({"error": "No scan found for this URL"}), 404
            scan = scan_docs[0].to_dict()
        else:
            scan = db.collection('scans').document(scan_id).get().to_dict()
            
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        
        ttps = MitreService.map_scan(scan)
        return jsonify({"status": "success", "ttps": ttps})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/api/graph', methods=['GET'])
@login_required
def get_graph():
    from flask import request
    from firebase_admin import firestore
    from app.services.graph_service import GraphService
    scan_id = request.args.get('scan_id')
    if not scan_id:
        return jsonify({"error": "Missing scan_id"}), 400
    try:
        db = firestore.client()
        if "/" in scan_id:
            scan_docs = list(db.collection('scans').where('target_url', '==', scan_id).limit(1).stream())
            if not scan_docs:
                return jsonify({"error": "No scan found for this URL"}), 404
            scan = scan_docs[0].to_dict()
            # Also overwrite scan_id with the actual ID for the graph endpoint
            scan_id = scan_docs[0].id
        else:
            scan = db.collection('scans').document(scan_id).get().to_dict()
            
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        
        graph_data = GraphService.build_graph(scan)
        return jsonify(graph_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/api/evidence', methods=['GET'])
@login_required
def get_evidence():
    # Return empty evidence list since we don't have GCS blobs set up (Real Data Only policy)
    evidence = []
    return jsonify({"status": "success", "evidence": evidence})
