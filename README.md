# Phishing URL Detector

A Python-based cybersecurity web application that analyzes website URLs and identifies potential phishing threats using rule-based security checks.

## Project Overview

The Phishing URL Detector helps users identify suspicious URLs by checking different URL characteristics and assigning a risk score between 0 and 100.

## Features

- URL analysis and risk scoring
- Phishing, Suspicious, and Low Risk classification
- 7 security checks
- HTTPS detection
- IP address detection
- Suspicious keyword detection
- URL length and special character analysis
- Domain pattern detection
- Embedded credential detection
- Dynamic dashboard statistics
- Scan history using SQLite
- Delete individual scan records
- Clear scan history
- Download scan history as CSV

## Technologies Used

- Python
- Flask
- HTML
- CSS
- SQLite
- CSV

## Project Structure

```text
Phishing-URL-Detector/
│
├── app.py
├── analyzer.py
├── scan_history.db
├── README.md
├── requirements.txt
│
└── templates/
    └── index.html
```

## Installation and Setup

1. Clone the repository:

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

2. Open the project folder:

```bash
cd Phishing-URL-Detector
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Run the application:

```bash
python app.py
```

5. Open your browser:

```text
http://127.0.0.1:5000
```

## How It Works

1. Enter a website URL.
2. Click the Analyze URL button.
3. The application performs security checks.
4. A risk score and detection result are displayed.
5. Scan results are stored in the SQLite database.
6. Users can view, delete, clear, and export scan history.

## Risk Classification

- LOW RISK – Low detected risk based on implemented checks.
- SUSPICIOUS – Some suspicious URL patterns detected.
- PHISHING – High risk score based on implemented checks.

## Important Note

This project uses rule-based URL analysis. It does not use machine learning or live threat-intelligence verification. A LOW RISK result does not guarantee that a website is safe.

## Author

Rajeswari Ramanaboina

B.Tech – Cybersecurity Student

GitHub: https://github.com/rajeswariramanaboina91

LinkedIn: https://linkedin.com/in/rajeswari-raji-891851300