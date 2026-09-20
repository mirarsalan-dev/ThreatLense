# ThreatLense Architecture

## Overview
ThreatLense is a highly modular, professional Cyber Threat Investigation Workstation. It utilizes a layered architecture separating routing, business logic, integrations, and ML intelligence, adhering to production-quality cybersecurity standards.

## Layers

### 1. Presentation Layer (Frontend)
- **UI:** A specialized Cyber Desktop environment (HTML5/CSS3/Vanilla JS) inspired by SOC (Security Operations Center) interfaces.
- **Modules:** Window-based investigation tools (URL Autopsy, Threat DNA, Threat Graph, OSINT, Threat Hunter).
- **Communication:** Standard RESTful API over HTTPS.

### 2. API Routing Layer
- Uses Flask Blueprints.
- **Endpoints:** Versioned APIs (e.g. `/api/scan`, `/api/osint`, `/api/graph`).
- **Security:** CSRF protections, strict Content-Security-Policies, and `login_required` middleware for Firebase Authentication.

### 3. Service Layer (Business Logic)
- **ScannerService:** Coordinates URL extraction and ML prediction pipelines.
- **OSINTService:** ThreadPoolExecutor-powered orchestration of concurrent external intelligence gathering (DNS, WHOIS, SSL).
- **GraphService:** Dynamic conversion of relational threat observables into nodes and edges for Vis.js representation.
- **MitreService:** Evidence-driven mapping of ML anomalies and content analysis to MITRE ATT&CK TTPs.

### 4. Data Layer (Firebase)
- **Firestore:** Non-relational storage for distributed documents.
  - `cases/`: Investigation contexts.
  - `scans/`: Snapshots of URL scanning and forensics.
- **Authentication:** Firebase Admin SDK verifying JWT ID Tokens.

## Security Controls
- **SSRF Prevention:** Strong isolation of the backend web fetching capabilities.
- **Data Integrity:** No mocked/falsified intelligence is allowed on the UI. All values represent authentic backend state.
- **Rate Limiting:** Managed at the API routing layer.
