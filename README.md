# Digital Forensic Evidence Tracking System

## About the Project

The Digital Forensic Evidence Tracking System is a web-based application designed to help track digital evidence and verify its integrity.

The application allows users to upload digital evidence and generate a SHA-256 hash for the uploaded file. The generated hash can be used to verify whether the evidence has remained unchanged.

## Key Features

- Upload digital evidence/files
- Generate SHA-256 hash values
- Verify file integrity
- Track digital evidence
- Web-based interface for interacting with the application

## How It Works

1. The user uploads a digital evidence file.
2. The application processes the uploaded file.
3. A SHA-256 hash is generated for the file.
4. The hash can be used to verify the integrity of the evidence.
5. Changes to the file can be identified by comparing hash values.

## Technologies Used

- Python
- Flask
- SQLite
- HTML
- CSS
- SHA-256

## Project Structure

```text
forensic-project/
│
├── app.py
├── forensic.py
├── templates/
├── static/
├── forensic.db
├── uploads/
├── requirements.txt
└── README.md
