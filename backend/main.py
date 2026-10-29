from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import google.generativeai as genai
import os
from typing import Optional, List
import base64
import io
from pypdf import PdfReader
from dotenv import load_dotenv
import re

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

# Configure Gemini API
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

class OfferCheckResponse(BaseModel):
    risk_score: int
    verdict: str
    red_flags: List[str]
    reason_hinglish: str
    reason_odia: str


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

    # Image extraction via Gemini (if configured)
    if content_type.startswith("image/"):
        if not GEMINI_API_KEY:
            return ""
        try:
            model = genai.GenerativeModel("gemini-1.5-flash")
            prompt = (
                "Extract any text present in the image. Return only the extracted text; do not add any commentary. "
                "If there is no text, return an empty string."
            )
            response = model.generate_content([prompt, content])
            extracted = response.text or ""
            return extracted.strip()
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

    # Check lines for exact suspicious quotes
    for ln in lines:
        low = ln.lower()
        if re.search(r"[\w.+-]+@(gmail|yahoo)\.com\b", low):
            checks["personal_email"] = True
            checks["suspicious_lines"].append(ln)
        if any(k in low for k in ["registration fee", "training fee", "security deposit", "upi", "pay now", "payment"]):
            checks["fee_keywords"] = True
            checks["suspicious_lines"].append(ln)
        # missing CIN/address: look for words like 'CIN' or 'company identification' or 'address'
        if "cin" not in low and "company" in low and ("address" not in low and "registered office" not in low):
            # This is a weak heuristic; we'll mark missing_cin if company mentioned but no address or cin lines found
            checks.setdefault("company_mentioned", True)

    # Determine missing CIN more robustly
    if any("cin" not in l.lower() for l in lines) and any("company" in l.lower() for l in lines):
        # If company mentioned but no line contains 'cin' or 'corporate identification number'
        if not any('cin' in l.lower() for l in lines):
            checks["missing_cin"] = True

    return checks


def compose_gemini_prompt(text: str, checks: dict) -> str:
    """Compose a prompt combining the offer text and the results of local checks for Gemini analysis."""
    prompt = "You are an expert in identifying fake job/internship offers for Indian students.\n"
    prompt += "Here is the offer text to analyze:\n\n" + text + "\n\n"
    prompt += "Local verification results:\n"
    prompt += f"- personal_email_flag: {checks.get('personal_email')}\n"
    prompt += f"- fee_keywords_flag: {checks.get('fee_keywords')}\n"
    prompt += f"- missing_cin_flag: {checks.get('missing_cin')}\n"
    suspicious = checks.get('suspicious_lines', [])
    if suspicious:
        prompt += "- suspicious_lines:\n"
        for s in suspicious:
            prompt += f"  - {s}\n"

    prompt += "\nBased on the above, provide a JSON response ONLY with these keys:\n"
    prompt += "{\n  \"risk_score\": number 0-100,\n  \"verdict\": \"Safe\"|\"Suspicious\"|\"Likely Scam\",\n  \"red_flags\": [\"exact suspicious quotes\"],\n  \"reason_hinglish\": \"2-3 simple sentences in Hinglish\",\n  \"reason_odia\": \"2-3 simple sentences in Odia\"\n}\n"
    prompt += "Do not add any extra keys or commentary. Keep reasons short and simple."
    return prompt


def analyze_with_gemini_prompt(prompt: str) -> dict:
    """Send prompt to Gemini and parse JSON response."""
    if not GEMINI_API_KEY:
        # Fallback simple heuristic
        return {
            "risk_score": 60,
            "verdict": "Suspicious",
            "red_flags": ["No Gemini API key configured; returning heuristic result"],
            "reason_hinglish": "Gemini API key missing, basic checks applied.",
            "reason_odia": "Gemini API key missing, basic checks applied."
        }

    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt)
        resp_text = response.text or ""
        # Extract JSON
        start = resp_text.find('{')
        end = resp_text.rfind('}') + 1
        if start != -1 and end > start:
            import json
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
            "red_flags": ["Gemini API error"],
            "reason_hinglish": "Gemini API error.",
            "reason_odia": "Gemini API error."
        }


@app.post("/check-offer")
async def check_offer(offer_text: str = Form(...), file: Optional[UploadFile] = File(None)):
    if not offer_text and not file:
        raise HTTPException(status_code=400, detail="Provide offer text or upload a file")

    combined_text = offer_text or ""

    # If file provided, extract text and append
    if file:
        extracted = await extract_text_from_file(file)
        if extracted:
            combined_text += "\n" + extracted

    # Run local verification checks
    checks = run_local_checks(combined_text)

    # Compose prompt and call Gemini
    prompt = compose_gemini_prompt(combined_text, checks)
    gemini_result = analyze_with_gemini_prompt(prompt)

    # Normalize and return
    risk_score = int(min(max(gemini_result.get('risk_score', 50), 0), 100))
    verdict = gemini_result.get('verdict', 'Suspicious')
    red_flags = gemini_result.get('red_flags', [])
    reason_hinglish = gemini_result.get('reason_hinglish', '')
    reason_odia = gemini_result.get('reason_odia', '')

    return {
        'risk_score': risk_score,
        'verdict': verdict,
        'red_flags': red_flags,
        'reason_hinglish': reason_hinglish,
        'reason_odia': reason_odia
    }
