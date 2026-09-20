<div align="center">
  <img src="https://img.icons8.com/color/120/000000/security-checked--v1.png" alt="ThreatLense Logo"/>
  <h1>🛡️ ThreatLense</h1>
  <p>
    <strong>A Next-Generation Cybersecurity Threat Intelligence & URL Analysis Platform</strong>
  </p>

  <p>
    <a href="#features">Features</a> •
    <a href="#tech-stack">Tech Stack</a> •
    <a href="#installation">Installation</a> •
    <a href="#architecture">Architecture</a>
  </p>

  <p>
    <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python" alt="Python Version" />
    <img src="https://img.shields.io/badge/Flask-3.0.3-lightgrey?style=for-the-badge&logo=flask" alt="Flask" />
    <img src="https://img.shields.io/badge/Firebase-Admin-orange?style=for-the-badge&logo=firebase" alt="Firebase" />
    <img src="https://img.shields.io/badge/Machine%20Learning-Scikit--Learn-yellow?style=for-the-badge&logo=scikit-learn" alt="Scikit-Learn" />
  </p>
</div>

---

## ⚡ Overview

**ThreatLense** empowers security researchers and incident responders by providing a centralized command center to analyze, track, and investigate potential web threats. Combining the power of **Machine Learning**, **Open Source Intelligence (OSINT)**, and **Web Forensics**, ThreatLense offers unparalleled visibility into the malicious web landscape.

---

## ✨ Key Features

| Feature | Description |
| :--- | :--- |
| 🧠 **ML URL Scanner** | Evaluates target URLs for phishing and malicious intent. Assigns a risk score based on deep structural features and heuristics. |
| 🕵️ **OSINT Automation** | Automatically aggregates domain intelligence, WHOIS data, and external correlations to build a complete threat profile. |
| 🔬 **Web Forensics** | Performs deep forensics including DOM and JavaScript analysis on suspicious targets to uncover obfuscated code. |
| 📊 **Command Center** | A real-time dashboard for monitoring system health, active authentication sessions, blocked requests, and recent scan logs. |
| 🧬 **Case Management** | Centralized investigation tracking featuring **Threat Timelines**, **Threat Graphs**, and **Threat DNA** visual correlations. |
| 🌐 **MITRE & STIX** | Automatically maps detected capabilities to the **MITRE ATT&CK** framework and exports intelligence in standard **STIX** bundle format. |
| 🛡️ **Self-Defense Engine** | Built-in robust protections including Role-Based Access Control (RBAC), CSRF tokens, strict security headers, and SSRF restrictions. |

---

## 🛠️ Tech Stack

### Backend & Infrastructure
- **Core Framework**: Python, Flask
- **Database & Auth**: Firebase Admin SDK (Firestore Database)
- **Deployment**: Docker & Docker Compose (Included)

### Intelligence Engine
- **Machine Learning**: Scikit-Learn (Random Forest Models & Feature Extraction)
- **Data Gathering & OSINT**: `dnspython`, `python-whois`, `tldextract`, `beautifulsoup4`

### Frontend UI
- **Technologies**: HTML5, CSS3, JavaScript (Vanilla), optimized for modern browsers.

---

## 🚀 Setup & Installation

### Prerequisites
- **Python 3.10+** installed on your system.
- A **Firebase Project** with a generated `serviceAccountKey.json`.

### 1. Clone the Repository
```bash
git clone https://github.com/mirarsalan-dev/ThreatLense.git
cd ThreatLense
```

### 2. Environment Setup (Recommended)
Navigate to the `Backend` directory, then create and activate an isolated Python virtual environment:
```bash
cd Backend
python -m venv venv

# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configuration
- Create a `.env` file in the `Backend` directory (you can use `.env.example` as a template).
- Place your Firebase Admin SDK credential file in the `Backend` directory and name it `serviceAccountKey.json`.

### 5. Launch ThreatLense (Locally)
```bash
python app.py
```
> 🎉 **Success!** The application will be accessible at `http://127.0.0.1:5000`.

### Alternative: Launch with Docker
You can easily spin up both the Frontend and Backend using Docker Compose from the project root:
```bash
docker-compose up --build
```

---

## 🔒 Security Notice

ThreatLense is designed by security professionals, for security professionals. 
The application includes a `self_defense.py` engine that strictly monitors and controls incoming requests. 

> [!WARNING]
> Ensure `SESSION_COOKIE_SECURE = False` is set in your configuration if you are running over HTTP during local development. In production environments, always deploy behind HTTPS.

---

## 📜 License

Distributed under the **MIT License**. See `LICENSE` for more information.

<div align="center">
  <sub>Built with ❤️ for a safer web.</sub>
</div>
