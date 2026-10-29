Scam Shield

Scam Shield
===========

Problem statement
-----------------
Many Indian students receive internship/job offers that may be fraudulent. Quick checks are often missing and victims lose money or expose sensitive documents. High-level motivating numbers (illustrative):

- About 2 in 3 fresh graduates face difficulty finding legitimate jobs or internships soon after graduation (employment mismatch and reporting surveys).
- Reports estimate cyber fraud losses in India across categories can be in the tens of thousands of crores; this README references ~₹55,000 Crore as a contextual figure for online fraud impacts in recent years.

Project overview
----------------
Scam Shield is a lightweight demo that helps Indian students quickly check internship/job offers for common scam indicators. It combines local verification checks and optional Google Gemini (Generative AI) analysis.

Key features
------------
- Gemini OCR: extract text from images using Google Generative AI (when GEMINI_API_KEY is provided).
- PDF text extraction using pypdf.
- Verification tools:
  - Flags personal email domains (e.g. @gmail.com, @yahoo.com) used for HR contact.
  - Detects fee/payment keywords (registration fee, training fee, security deposit, UPI, pay now, payment).
  - Heuristic detection for missing company CIN/address information.
- Gemini-assisted scoring & multilingual reasons:
  - Sends the offer text + verification results to Google Gemini (if configured) and asks for a JSON response containing risk_score, verdict, red_flags, and short reasons in Hinglish and Odia.
- Simple, friendly frontend with:
  - Paste/upload offer, sample test buttons (Safe / Suspicious / Scam), color-coded results card.
  - Copy-to-clipboard actions to generate a cybercrime complaint draft (for cybercrime.gov.in) and a short TPO/class WhatsApp alert message.

Project structure
-----------------
- backend/
  - main.py          — FastAPI backend with extraction, verification, and Gemini integration
  - requirements.txt — Python dependencies
- frontend/
  - index.html       — Tailwind + vanilla JS frontend
- tests/
  - test_main.py     — pytest tests using FastAPI TestClient
- README.md
- LICENSE

How it works (short)
--------------------
1. Frontend sends offer text (and optional file) to backend /check-offer endpoint.
2. Backend extracts text from PDFs (pypdf) or images (Gemini OCR) where available.
3. Backend runs local verification checks (email domain, fee keywords, missing CIN heuristics) and composes a prompt for Gemini.
4. Gemini (if configured via GEMINI_API_KEY) returns a structured JSON with risk_score (0-100), verdict (Safe/Suspicious/Likely Scam), red_flags (exact suspicious quotes) and short reasons in Hinglish and Odia.
5. Frontend displays results in a color-coded card and provides quick copy actions for reporting/alerting.

Running locally on Windows (step-by-step)
----------------------------------------
Prerequisites:
- Python 3.10+ installed and on PATH
- Optional: A Google Gemini (Generative AI) API key if you want OCR and model-based analysis

1) Clone or download the project and open PowerShell in the project root.

2) Backend setup

   cd backend

   # Create virtual environment
   python -m venv .venv

   # Activate virtualenv (PowerShell)
   .\.venv\Scripts\Activate.ps1

   # Install dependencies
   pip install -r requirements.txt

   # (Optional) set GEMINI_API_KEY environment variable in PowerShell for Gemini features
   $env:GEMINI_API_KEY = "your_gemini_api_key_here"

   # Start the backend server
   uvicorn main:app --reload --host 127.0.0.1 --port 8000

   The API will be available at http://127.0.0.1:8000

3) Frontend

   The simplest option is to open frontend/index.html in your browser (double-click the file).
   Alternatively you can serve it with a tiny server (recommended):

   # From project root
   cd frontend
   python -m http.server 5500

   Open http://127.0.0.1:5500 in your browser.

4) Tests

   From project root, with backend virtualenv activated and dependencies installed, run:

   pytest -q

Notes and caveats
-----------------
- Gemini integration is optional. If you do not set GEMINI_API_KEY the backend will use a rule-based heuristic and still return results.
- PDF extraction uses pypdf. Image OCR relies on the Gemini model and will only work if you provide a valid GEMINI_API_KEY.
- This project is a demo tool. Do not upload sensitive personal documents to untrusted environments. Use this tool as an aid and always verify independently.

Built with
----------
- AgentFoundry SMART-Code IDE

Contributing
------------
Contributions are welcome — open issues or PRs with improvements (better CIN detection, WHOIS checks, more Indian-language outputs, etc.).

License
-------
This project is licensed under the MIT License — see LICENSE file for details.
