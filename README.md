🛡️ SecureScan
Automated File and URL Threat Analyzer

SecureScan is a Python and Flask-based cybersecurity application designed to analyze files and URLs for common suspicious indicators. It provides explainable risk scores, scan history, cryptographic file hashes, authentication, and optional external threat-intelligence integration.

Features

🔗 URL threat analysis

📁 Static file analysis

🔐 User registration and login

📊 Explainable risk scoring

🧾 Scan history

🔑 MD5, SHA-1 and SHA-256 hashing

📄 JSON security reports

🌐 Optional threat-intelligence integration

📱 Responsive web interface

Technology Stack

Python

Flask

SQLite

HTML5

CSS3

JavaScript

Requests

python-dotenv

Project Structure
SecureScan/
├── app.py
├── config.py
├── requirements.txt
├── analyzers/
├── auth/
├── database/
├── services/
├── templates/
└── static/

Installation

Clone the repository:

git clone https://github.com/YOUR_USERNAME/SecureScan.git
cd SecureScan


Create a virtual environment:

python -m venv venv


Windows:

venv\Scripts\activate


Linux/macOS:

source venv/bin/activate


Install dependencies:

pip install -r requirements.txt


Create .env from .env.example and configure the required values.

Run the application:

python app.py


Open:

http://127.0.0.1:5000

Risk Classification
Score	Classification
0–24	Low
25–49	Medium
50–74	High
75–100	Critical
Security Notes

Uploaded files are analyzed statically and should never be executed by the application. File uploads should be handled in an isolated environment when deploying this project.

Never commit API keys, passwords, .env files, databases, or sensitive user data to GitHub.

Disclaimer

SecureScan is intended for defensive cybersecurity research and educational purposes. Results are heuristic indicators and should not be treated as definitive proof that a file or URL is malicious.

License

This project can be released under the MIT License.
