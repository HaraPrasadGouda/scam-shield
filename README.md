Scam Shield
===========

Problem statement
-----------------
Many Indian students receive internship/job offers that may be fraudulent. Quick checks are often missing and victims lose money or expose sensitive documents. 

- Graduates are 2 in 3 of India's jobless youth (India Today, Jul 2026).
- Total cyber fraud in India crossed Rs 55,000 crore (Centre, Jul 2026).

Project overview
----------------
Scam Shield is a lightweight AI-powered demo that helps Indian students quickly check internship/job offers for common scam indicators. It combines local heuristic verification, WHOIS domain age checks, MCA company verification links, and Google Gemini Generative AI analysis.

Live Demo
---------
[Live Demo Link Placeholder - Deploy to Cloud Run / Vercel / Render]

Screenshots
-----------
| Home Screen & Dark Navy Gradient | Risk Analysis & Red Flag Cards |
| :---: | :---: |
| *[Screenshot Placeholder: UI Dashboard]* | *[Screenshot Placeholder: Risk Gauge & Red Flags]* |

Key features
------------
- **Shield Logo & Tagline**: "Check any internship offer in 10 seconds".
- **Dark Navy Gradient & Glassmorphism UI**: Modern aesthetic with Tailwind CSS.
- **Big Circular Risk-Score Gauge**: Clear green, amber, and red risk assessment.
- **Red Flag Cards**: Highlight exact suspicious lines and quotes with clear icons.
- **WHOIS Domain Age Check**: Automatic domain lookup (`python-whois`); domains under 6 months old are flagged as high scam risk.
- **MCA Verification**: Extracts company names and CIN, providing a direct manual verification link to the MCA Company Master Data portal.
- **Hinglish / Odia Toggle Tabs**: Multilingual explanations tailored for students.
- **Drag-Drop Upload Zone**: Supports PDF and image upload with Gemini OCR.
- **Action Copiers**: Instant copy buttons for Cybercrime complaints (`cybercrime.gov.in`) and TPO/WhatsApp class alert messages.

Project structure
-----------------
- backend/
  - main.py          — FastAPI backend with extraction, WHOIS/MCA tools, and google-genai integration
  - requirements.txt — Python dependencies
  - tools/
    - whois_check.py — Domain age WHOIS checks and MCA lookup helpers
- frontend/
  - index.html       — Tailwind + vanilla JS frontend (served directly from FastAPI at `/`)
- tests/
  - test_main.py     — pytest tests using FastAPI TestClient
- README.md
- LICENSE

Running locally on Windows (step-by-step)
----------------------------------------
Prerequisites:
- Python 3.10+ installed and on PATH
- Google Gemini API key (`GEMINI_API_KEY`)

1) Clone or download the project and open PowerShell in the project root.

2) Backend setup & Server
   cd backend
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt

   # Set environment variables
   $env:GEMINI_API_KEY = "your_gemini_api_key_here"
   $env:GEMINI_MODEL = "gemini-2.5-flash"

   # Start the backend server (serves both API and frontend at root)
   uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000

   Open http://127.0.0.1:8000 in your browser.

3) Running Tests
   pytest -q

Notes and caveats
-----------------
- Gemini integration uses the official `google-genai` SDK and `GEMINI_MODEL` (default `gemini-2.5-flash`).
- WHOIS checks require internet access to query registrar databases.
- This project is a demo tool. Do not upload sensitive personal documents to untrusted environments.

License
-------
This project is licensed under the MIT License — see LICENSE file for details.
