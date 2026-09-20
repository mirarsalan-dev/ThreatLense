# ThreatLense API Documentation

All endpoints require a valid Firebase ID Token passed in the `Authorization` or via secure session cookies.

## Endpoints

### 1. `POST /api/scan`
Submits a new URL target for full pipeline analysis.
**Payload:**
```json
{
  "url": "http://suspicious-site.com",
  "case_id": "CASE-1234"
}
```
**Response:**
Returns a detailed scan document including `scan_id`, `risk_score`, `verdict`, and extracted ML features.

### 2. `GET /api/osint?target=<url>`
Performs a live out-of-band external intelligence check.
**Query Params:** `target` (The URL to analyze)
**Returns:** DNS Records (A, AAAA, MX, NS, TXT), WHOIS data, and SSL Certificate parameters.

### 3. `GET /api/graph?scan_id=<scan_id>`
Generates a deterministic threat-correlation graph.
**Returns:** A `vis-network` compatible payload consisting of `{ "nodes": [...], "edges": [...] }`.

### 4. `GET /api/mitre?scan_id=<scan_id>`
Maps anomalous structural elements and OSINT indicators to MITRE ATT&CK TTPs.
**Returns:** Categorized TTPs matching the `Initial Access`, `Execution`, `Defense Evasion`, and `Credential Access` tactics.

### 5. `GET /api/evidence`
Retrieves forensic artifacts attached to scans (DOM dumps, PCAPs, STIX bundles).

### 6. `GET /api/health`
Monitors system observability and component statuses.
