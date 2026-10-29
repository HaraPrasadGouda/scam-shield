from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel
from google import genai
from google.genai import types
import os
from typing import Optional, List, Dict, Any
import io
from pypdf import PdfReader
from dotenv import load_dotenv
import re
import json

from backend.tools.whois_check import run_whois_and_mca_checks

# Load environment variables from .env (if present)
load_dotenv()

app = FastAPI(title="Scam Shield API")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure Gemini API using google-genai SDK
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

# Initialize Gemini client
try:
    if GEMINI_API_KEY:
        client = genai.Client(api_key=GEMINI_API_KEY)
    else:
        client = genai.Client()
except Exception as e:
    print(f"Gemini client initialization warning: {e}")
    client = None


class OfferCheckResponse(BaseModel):
    risk_score: int
    verdict: str
    red_flags: List[str]
    reason_hinglish: str
    reason_odia: str
    mca_info: Optional[Dict[str, Any]] = None
    domain_reports: Optional[List[Dict[str, Any]]] = None


@app.get("/")
async def serve_index():
    """Serve frontend/index.html at root '/'."""
    frontend_path = os.path.join(os.path.dirname(__file__), "../frontend/index.html")
    if os.path.exists(frontend_path):
        return FileResponse(frontend_path)
    return HTMLResponse("<h1>Scam Shield API is running. frontend/index.html not found.</h1>", status_code=200)


async def extract_text_from_file(file: UploadFile) -> str:
    """Extract text from an uploaded file using pypdf for PDFs and Gemini OCR for images."""
    content = await file.read()
    content_type = file.content_type or ""

    # PDF extraction
    if content_type == "application/pdf" or file.filename.lower().endswith('.pdf'):
        try:
            reader = PdfReader(io.BytesIO(content))
            text_parts = []
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)
            return "\n".join(text_parts)
        except Exception as e:
            print(f"PDF extraction error: {e}")
            return ""

    # Image extraction via Gemini OCR
    if content_type.startswith("image/"):
        if not client:
            return ""
        try:
            prompt = (
                "Extract any text present in the image. Return only the extracted text; do not add any commentary. "
                "If there is no text, return an empty string."
            )
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=[
                    prompt,
                    types.Part.from_bytes(data=content, mime_type=content_type)
                ]
            )
            return (response.text or "").strip()
        except Exception as e:
            print(f"Gemini OCR error: {e}")
            return ""

    return ""


def run_local_checks(text: str) -> dict:
    """Run simple verification checks:
    - flag personal email domains (@gmail.com, @yahoo.com)
    - detect fee keywords (registration fee, training fee, security deposit, UPI)
    - check missing CIN or address indicators
    - collect exact suspicious quotes/lines
    """
    checks = {
        "personal_email": False,
        "fee_keywords": False,
        "missing_cin": False,
        "suspicious_lines": []
    }

    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]

    for ln in lines:
        low = ln.lower()
        if re.search(r"[\w.+-]+@(gmail|yahoo)\.com\b", low):
            checks["personal_email"] = True
            checks["suspicious_lines"].append(ln)
        if any(k in low for k in ["registration fee", "training fee", "security deposit", "upi", "pay now", "payment", "security money"]):
            checks["fee_keywords"] = True
            checks["suspicious_lines"].append(ln)

    if any("cin" not in l.lower() for l in lines) and any("company" in l.lower() for l in lines):
        if not any('cin' in l.lower() for l in lines):
            checks["missing_cin"] = True

    return checks


def compose_gemini_prompt(text: str, checks: dict, whois_result: dict) -> str:
    """Compose a prompt combining the offer text, local checks, and WHOIS/MCA results for Gemini analysis."""
    prompt = "You are an expert in identifying fake job/internship offers for Indian students.\n"
    prompt += "Here is the offer text to analyze:\n\n" + text + "\n\n"
    prompt += "Local verification results:\n"
    prompt += f"- personal_email_flag: {checks.get('personal_email')}\n"
    prompt += f"- fee_keywords_flag: {checks.get('fee_keywords')}\n"
    prompt += f"- missing_cin_flag: {checks.get('missing_cin')}\n"
    
    suspicious = checks.get('suspicious_lines', [])
    whois_flags = whois_result.get('red_flags', [])
    all_suspicious = suspicious + whois_flags
    
    if all_suspicious:
        prompt += "- suspicious_lines or domain red flags:\n"
        for s in all_suspicious:
            prompt += f"  - {s}\n"

    prompt += "\nBased on the above, provide a JSON response ONLY with these keys:\n"
    prompt += "{\n  \"risk_score\": number 0-100,\n  \"verdict\": \"Safe\"|\"Suspicious\"|\"Likely Scam\",\n  \"red_flags\": [\"exact suspicious quotes or red flag descriptions\"],\n  \"reason_hinglish\": \"2-3 simple sentences in Hinglish\",\n  \"reason_odia\": \"2-3 simple sentences in Odia\"\n}\n"
    prompt += "Do not add any extra keys or commentary. Keep reasons short and simple."
    return prompt


def analyze_with_gemini(prompt: str) -> dict:
    """Send prompt to Gemini and parse JSON response."""
    if not client:
        return {
            "risk_score": 60,
            "verdict": "Suspicious",
            "red_flags": ["No Gemini client/API key configured; returning heuristic result"],
            "reason_hinglish": "Gemini API key missing, basic security checks applied.",
            "reason_odia": "Gemini API key missing, basic security checks applied."
        }

    try:
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt
        )
        resp_text = response.text or ""
        start = resp_text.find('{')
        end = resp_text.rfind('}') + 1
        if start != -1 and end > start:
            return json.loads(resp_text[start:end])
        else:
            return {
                "risk_score": 50,
                "verdict": "Suspicious",
                "red_flags": ["Could not parse Gemini response"],
                "reason_hinglish": "Could not parse Gemini response.",
                "reason_odia": "Could not parse Gemini response."
            }
    except Exception as e:
        print(f"Gemini call error: {e}")
        return {
            "risk_score": 50,
            "verdict": "Suspicious",
            "red_flags": [f"Gemini API error: {e}"],
            "reason_hinglish": "Gemini API error occurred.",
            "reason_odia": "Gemini API error occurred."
        }


@app.post("/check-offer", response_model=OfferCheckResponse)
async def check_offer(offer_text: Optional[str] = Form(None), file: Optional[UploadFile] = File(None)):
    if not offer_text and not file:
        raise HTTPException(status_code=400, detail="Provide offer text or upload a file")

    combined_text = offer_text or ""

    if file:
        extracted = await extract_text_from_file(file)
        if extracted:
            combined_text += "\n" + extracted

    # Run local verification checks
    checks = run_local_checks(combined_text)

    # Run WHOIS and MCA checks
    whois_result = run_whois_and_mca_checks(combined_text)

    # Compose prompt and call Gemini
    prompt = compose_gemini_prompt(combined_text, checks, whois_result)
    gemini_result = analyze_with_gemini(prompt)

    # Normalize risk score and verdict
    risk_score = int(min(max(gemini_result.get('risk_score', 50), 0), 100))
    verdict = gemini_result.get('verdict', 'Suspicious')
    
    # Combine gemini red_flags with whois red_flags and suspicious lines
    gemini_red_flags = gemini_result.get('red_flags', [])
    whois_red_flags = whois_result.get('red_flags', [])
    
    # Merge unique red flags
    combined_red_flags = list(dict.fromkeys(gemini_red_flags + whois_red_flags))
    if not combined_red_flags and risk_score > 30:
        combined_red_flags = checks.get('suspicious_lines', ["Potential scam indicators detected in text format."])

    reason_hinglish = gemini_result.get('reason_hinglish', 'Yeh offer thoda suspicious lag raha hai. Kripya savdhan rahein aur koi paise na dein.')
    reason_odia = gemini_result.get('reason_odia', 'ଏହି ଅଫରଟି ସନ୍ଦିଗ୍ଧ ଜଣାପଡୁଛି। ଦୟାକରି ସତର୍କ ରୁହନ୍ତୁ ଏବଂ କୌଣସି ଟଙ୍କା ଦିଅନ୍ତୁ ନାହିଁ।')

    return {
        'risk_score': risk_score,
        'verdict': verdict,
        'red_flags': combined_red_flags,
        'reason_hinglish': reason_hinglish,
        'reason_odia': reason_odia,
        'mca_info': whois_result.get('mca_info'),
        'domain_reports': whois_result.get('domains_checked')
    }
