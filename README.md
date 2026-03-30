# PQC Scanner

A Post-Quantum Cryptography risk assessment and migration planning tool. Scans TLS endpoints and assesses their current cryptographic posture against emerging quantum threats (like Shor's and Grover's algorithms) and Harvest Now Decrypt Later (HNDL) attacks.

## Features
* **Full Cryptographic Assessment**: Parses TLS ciphers, public keys, and certificate chains.
* **Quantum Heatmap & Timelines**: Predicts when your assets become vulnerable to quantum decryption based on their key strength.
* **Risk Engine**: Scores assets based on classical vulnerabilities, PQC readiness, and endpoint data sensitivity.
* **HNDL Analysis**: Specialized threat modeling for Harvest Now Decrypt Later exposure.
* **PQC Migration Planner**: Automatically generates phase-by-phase migration plans mapping current algorithms to NIST standards (CRYSTALS-Kyber/Dilithium).
* **CBOM Generation**: Exports full Cryptographic Bill of Materials in CycloneDX format.

## Quickstart

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Setup postgres and redis, then configure your `.env` file for credentials.

3. Initialize the database and scan some simple seeds:
   ```bash
   python scripts/seed_data.py
   ```

4. Run the FastAPI development server:
   ```bash
   uvicorn backend.main:app --reload
   ```

5. (Optional) Run the Celery Worker for async scans:
   ```bash
   celery -A workers.scan_worker.celery_app worker --loglevel=info
   ```

## API Documentation

Once running, interact with the API via the swagger docs: `http://localhost:8000/docs`
