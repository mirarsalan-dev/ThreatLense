# ThreatLense

ThreatLense is a comprehensive Cybersecurity Threat Intelligence and URL Analysis web application. It acts as a centralized platform for security researchers to analyze, track, and investigate potential web threats using Machine Learning, Open Source Intelligence (OSINT), and Web Forensics.

## Features

- **Machine Learning URL Scanner**: Evaluates target URLs for phishing and malicious intent, assigning a risk score based on structural features and heuristics.
- **OSINT & Forensics Automation**: Automatically gathers domain intelligence and performs deep web forensics (e.g., DOM and JavaScript analysis) on suspicious targets.
- **Command Center Dashboard**: Real-time monitoring of system health, active authentication sessions, blocked requests, and recent scan logs.
- **Case Management**: Centralized investigation management featuring Threat Timelines, Threat Graphs, and "Threat DNA" visual correlations.
- **MITRE & STIX Integration**: Automatically maps detected capabilities to the MITRE ATT&CK framework and allows exporting intelligence in STIX bundle format.
- **Built-in Self-Defense Engine**: Integrates robust protections including Role-Based Access Control (RBAC), CSRF tokens, strict security headers, and SSRF restrictions.

## Tech Stack

- **Backend**: Python, Flask
- **Database & Auth**: Firebase Admin SDK (Firestore Database)
- **Machine Learning**: Scikit-Learn (Random Forest Models)
- **Data Gathering**: dnspython, python-whois, tldextract, beautifulsoup4
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)

## Setup & Installation

### Prerequisites
- Python 3.10+
- A Firebase Project (with a generated `serviceAccountKey.json`)

### Installation Steps
1. **Clone the repository:**
   ```bash
   git clone https://github.com/mirarsalan-dev/ThreatLense.git
   cd ThreatLense
   ```

2. **Set up a Virtual Environment (Recommended):**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Variables & Firebase Credentials:**
   - Create a `.env` file in the root directory (refer to `.env.example`).
   - Place your Firebase Admin SDK credential file in the root directory as `serviceAccountKey.json`.

5. **Run the Application:**
   ```bash
   python app.py
   ```
   The application will be accessible at `http://127.0.0.1:5000`.

## Security Notice
This application comes with a `self_defense.py` engine that strictly controls incoming requests. Make sure your local setup sets `SESSION_COOKIE_SECURE = False` if you are running it over HTTP during development. In production, always use HTTPS.

## License
MIT License
