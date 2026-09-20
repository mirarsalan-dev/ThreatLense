import hashlib
import uuid
import datetime
from firebase_admin import firestore
from app.services.audit_service import AuditService

class EvidenceService:
    @staticmethod
    def create_evidence(case_id, file_name, raw_content, content_type="text/html", user_id="system"):
        """
        Creates an evidence record with a SHA-256 hash and initiates the Chain of Custody.
        """
        try:
            # 1. Evidence Hashing (SC-77)
            if isinstance(raw_content, str):
                raw_content = raw_content.encode('utf-8')
            
            evidence_hash = hashlib.sha256(raw_content).hexdigest()
            evidence_id = str(uuid.uuid4())
            
            db = firestore.client()
            
            # 2. Chain of Custody (SC-78)
            coc_entry = {
                "action": "CREATED",
                "timestamp": firestore.SERVER_TIMESTAMP,
                "actor": user_id,
                "hash": evidence_hash
            }
            
            evidence_data = {
                "id": evidence_id,
                "case_id": case_id,
                "file_name": file_name,
                "content_type": content_type,
                "size_bytes": len(raw_content),
                "sha256": evidence_hash,
                "chain_of_custody": [coc_entry],
                "created_at": firestore.SERVER_TIMESTAMP
            }
            
            db.collection('evidence').document(evidence_id).set(evidence_data)
            
            AuditService.log_security_event('EVIDENCE_CREATED', 'INFO', 'ALLOWED', reason='New evidence collected and hashed', resource=evidence_id)
            
            return evidence_data
            
        except Exception as e:
            print(f"Error creating evidence: {e}")
            return None
            
    @staticmethod
    def access_evidence(evidence_id, user_id):
        """
        Records an access event in the chain of custody.
        """
        try:
            db = firestore.client()
            evidence_ref = db.collection('evidence').document(evidence_id)
            
            coc_entry = {
                "action": "VIEWED",
                "timestamp": firestore.SERVER_TIMESTAMP,
                "actor": user_id
            }
            
            evidence_ref.update({
                "chain_of_custody": firestore.ArrayUnion([coc_entry])
            })
            
            AuditService.log_security_event('EVIDENCE_ACCESSED', 'INFO', 'ALLOWED', reason='Evidence viewed by analyst', resource=evidence_id)
            return True
        except Exception as e:
            return False
