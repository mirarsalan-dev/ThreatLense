# ThreatLense Deployment Guide

## Prerequisites
- Docker & Docker Compose
- Firebase Project configured (Firestore, Auth)
- `.env` and `serviceAccountKey.json` configured in root directory.

## Development Environment
Run the lightweight Flask server using standard Python:
```bash
pip install -r requirements.txt
python app.py
```

## Production Docker Environment
The production configuration wraps the backend in a containerized structure and scales the worker.

**Build and Run:**
```bash
docker-compose up --build -d
```

**Check Logs:**
```bash
docker-compose logs -f web
```

**Environment Variables:**
Refer to `.env.example`. Make sure that `FIREBASE_CREDENTIALS_PATH` is correctly mapped inside the container volume.
