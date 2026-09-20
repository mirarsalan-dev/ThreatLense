from firebase_admin import firestore
import time
import uuid

class DBService:
    @staticmethod
    def create_case(title, target, priority="Medium", description=""):
        """Creates a new Cyber Investigation Case."""
        try:
            db = firestore.client()
            case_id = f"CASE-{int(time.time())}"
            case_data = {
                "case_id": case_id,
                "title": title,
                "target": target,
                "priority": priority,
                "description": description,
                "status": "Open",
                "created_at": int(time.time()),
                "tags": []
            }
            db.collection('cases').document(case_id).set(case_data)
            return case_data
        except Exception as e:
            print(f"Error creating case: {e}")
            return None

    @staticmethod
    def get_cases(limit=50):
        """Retrieves recent cases."""
        try:
            db = firestore.client()
            docs = db.collection('cases').order_by('created_at', direction=firestore.Query.DESCENDING).limit(limit).stream()
            return [doc.to_dict() for doc in docs]
        except Exception as e:
            print(f"Error fetching cases: {e}")
            return []

    @staticmethod
    def save_scan(scan_data):
        """
        Saves a scan report to Firestore under the 'scans' collection.
        """
        try:
            db = firestore.client()
            scan_id = scan_data.get("scan_id")
            if not scan_id:
                return None
            db.collection('scans').document(scan_id).set(scan_data)
            return scan_id
        except Exception as e:
            print(f"Error saving scan: {e}")
            return None

    @staticmethod
    def record_timeline_event(case_id, event_type, description, source="SYSTEM"):
        """Records a chronological forensic event for a case."""
        if not case_id:
            return None
        try:
            db = firestore.client()
            event_id = f"EVT-{uuid.uuid4().hex[:8].upper()}"
            event_data = {
                "event_id": event_id,
                "case_id": case_id,
                "type": event_type,
                "description": description,
                "source": source,
                "timestamp": int(time.time())
            }
            db.collection('timeline_events').document(event_id).set(event_data)
            return event_id
        except Exception as e:
            print(f"Error recording timeline event: {e}")
            return None

    @staticmethod
    def get_recent_scans(limit=50):
        """
        Retrieves the most recent scans from Firestore, sorted by scan_id (which contains timestamp).
        """
        try:
            db = firestore.client()
            docs = db.collection('scans').order_by('scan_id', direction=firestore.Query.DESCENDING).limit(limit).stream()
            return [doc.to_dict() for doc in docs]
        except Exception as e:
            print(f"Error fetching from Firestore: {e}")
            return []

    @staticmethod
    def search_scans(query, limit=100):
        """
        Searches recent scans for a specific query string (URL or IP).
        Firestore lacks full-text search, so we fetch the recent 100 and filter in memory.
        """
        try:
            recent = DBService.get_recent_scans(limit=limit)
            if not query:
                return recent
            
            query = query.lower()
            results = []
            for scan in recent:
                url_match = query in scan.get('url', '').lower()
                ip_match = False
                if scan.get('osint') and scan['osint'].get('ip_addresses'):
                    ip_match = any(query in ip for ip in scan['osint']['ip_addresses'])
                
                if url_match or ip_match:
                    results.append(scan)
            return results
        except Exception as e:
            print(f"Error searching Firestore: {e}")
            return []
