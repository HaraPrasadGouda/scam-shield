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

# Load environment variables from backend/.env or project-root .env (whichever exists)
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(_BACKEND_DIR, ".env"))
load_dotenv(os.path.join(_BACKEND_DIR, "..", ".env"))

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
client = None
if GEMINI_API_KEY:
    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
    except Exception as e:
        print(f"Gemini client initialization warning: {e}")
else:
    print("GEMINI_API_KEY not set: running with rule-based scoring only")


class OfferCheckResponse(BaseModel):
    risk_score: int
    verdict: str
    red_flags: List[str]
    reason_hinglish: str
    reason_odia: str
    reasons: Dict[str, str] = {}
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


URGENCY_WORDS = ["within 24 hours", "within 2 hours", "within 48 hours", "limited seats", "immediately",
                 "urgent", "last chance", "otherwise the offer will be cancelled", "confirm your seat"]
EASY_MONEY_WORDS = ["only 2 hours", "work from home", "no experience", "earn rs", "earn ₹", "per day"]


LANGUAGES = ["en", "hinglish", "hi", "or", "bn", "ta", "te", "mr"]

# Plain-language explanations per verdict, used when Gemini is unavailable.
REASON_TEMPLATES = {
    "Safe": {
        "en": "No major red flags found in this offer. Still, verify the company on its official website and on MCA before joining.",
        "hinglish": "Is offer mein koi bada red flag nahi mila. Phir bhi company ki official website aur MCA pe naam check kar lo.",
        "hi": "इस ऑफ़र में कोई बड़ा खतरे का संकेत नहीं मिला। फिर भी जॉइन करने से पहले कंपनी की आधिकारिक वेबसाइट और MCA पर नाम जाँच लें।",
        "or": "ଏହି ଅଫରରେ କୌଣସି ବଡ଼ ବିପଦ ସଙ୍କେତ ମିଳିଲା ନାହିଁ। ତଥାପି ଯୋଗଦେବା ପୂର୍ବରୁ କମ୍ପାନୀର ଅଫିସିଆଲ ୱେବସାଇଟ ଓ MCA ରେ ନାମ ଯାଞ୍ଚ କରନ୍ତୁ।",
        "bn": "এই অফারে বড় কোনো বিপদের লক্ষণ পাওয়া যায়নি। তবুও যোগ দেওয়ার আগে কোম্পানির অফিসিয়াল ওয়েবসাইট ও MCA-তে নাম যাচাই করুন।",
        "ta": "இந்த வேலை வாய்ப்பில் பெரிய எச்சரிக்கை அறிகுறிகள் இல்லை. இருந்தாலும் சேருவதற்கு முன் நிறுவனத்தின் அதிகாரப்பூர்வ இணையதளம் மற்றும் MCA-வில் சரிபார்க்கவும்.",
        "te": "ఈ ఆఫర్‌లో పెద్ద ప్రమాద సంకేతాలు కనిపించలేదు. అయినా చేరే ముందు కంపెనీ అధికారిక వెబ్‌సైట్ మరియు MCAలో పేరు తనిఖీ చేయండి.",
        "mr": "या ऑफरमध्ये मोठे धोक्याचे संकेत आढळले नाहीत. तरीही रुजू होण्यापूर्वी कंपनीची अधिकृत वेबसाइट आणि MCA वर नाव तपासा."
    },
    "Suspicious": {
        "en": "This offer looks suspicious. Do not send any documents or money until you have verified the company.",
        "hinglish": "Yeh offer thoda suspicious hai. Company verify kiye bina koi document ya paise mat bhejo.",
        "hi": "यह ऑफ़र संदिग्ध लग रहा है। कंपनी की जाँच किए बिना कोई दस्तावेज़ या पैसे न भेजें।",
        "or": "ଏହି ଅଫର ସନ୍ଦେହଜନକ। କମ୍ପାନୀ ଯାଞ୍ଚ ନକରି କୌଣସି ଡକ୍ୟୁମେଣ୍ଟ କିମ୍ବା ଟଙ୍କା ପଠାନ୍ତୁ ନାହିଁ।",
        "bn": "এই অফারটি সন্দেহজনক। কোম্পানি যাচাই না করে কোনো নথি বা টাকা পাঠাবেন না।",
        "ta": "இந்த வேலை வாய்ப்பு சந்தேகத்திற்குரியது. நிறுவனத்தை சரிபார்க்கும் வரை எந்த ஆவணங்களையும் பணத்தையும் அனுப்ப வேண்டாம்.",
        "te": "ఈ ఆఫర్ అనుమానాస్పదంగా ఉంది. కంపెనీని ధృవీకరించే వరకు ఎలాంటి పత్రాలు లేదా డబ్బు పంపవద్దు.",
        "mr": "ही ऑफर संशयास्पद वाटते. कंपनीची खात्री केल्याशिवाय कोणतीही कागदपत्रे किंवा पैसे पाठवू नका."
    },
    "Likely Scam": {
        "en": "This offer looks like a scam. Do not pay any fee. Report it at cybercrime.gov.in or call 1930.",
        "hinglish": "Yeh offer scam lag raha hai. Koi bhi fee mat do, aur cybercrime.gov.in pe ya 1930 pe report karo.",
        "hi": "यह ऑफ़र धोखाधड़ी लग रहा है। कोई भी फीस न दें। cybercrime.gov.in पर या 1930 पर कॉल करके शिकायत करें।",
        "or": "ଏହି ଅଫରଟି ଠକେଇ ଭଳି ଲାଗୁଛି। କୌଣସି ଫି ଦିଅନ୍ତୁ ନାହିଁ। cybercrime.gov.in ରେ କିମ୍ବା 1930 ରେ ରିପୋର୍ଟ କରନ୍ତୁ।",
        "bn": "এই অফারটি প্রতারণা বলে মনে হচ্ছে। কোনো ফি দেবেন না। cybercrime.gov.in-এ বা 1930 নম্বরে অভিযোগ করুন।",
        "ta": "இது ஒரு மோசடி வேலை வாய்ப்பாகத் தெரிகிறது. எந்தக் கட்டணமும் செலுத்த வேண்டாம். cybercrime.gov.in அல்லது 1930 இல் புகார் செய்யவும்.",
        "te": "ఈ ఆఫర్ మోసంలా కనిపిస్తోంది. ఎలాంటి ఫీజు చెల్లించవద్దు. cybercrime.gov.in లో లేదా 1930 కి కాల్ చేసి ఫిర్యాదు చేయండి.",
        "mr": "ही ऑफर फसवणूक वाटते. कोणतीही फी भरू नका. cybercrime.gov.in वर किंवा 1930 वर तक्रार करा."
    }
}


def heuristic_result(text: str, checks: dict, whois_result: dict) -> dict:
    """Rule-based score used when Gemini is unavailable or fails."""
    low = text.lower()
    score = 10
    flags = []
    if checks.get("fee_keywords"):
        score += 40
        flags.append("Asks you to pay money (fee / deposit / UPI). Real companies never charge for a job.")
    if checks.get("personal_email"):
        score += 20
        flags.append("HR uses a free Gmail/Yahoo address instead of a company email.")
    urgent = [w for w in URGENCY_WORDS if w in low]
    if urgent:
        score += 15
        flags.append("Pressure tactics: " + ", ".join(f'"{w}"' for w in urgent[:3]))
    easy = [w for w in EASY_MONEY_WORDS if w in low]
    if easy:
        score += 10
        flags.append("Too-good-to-be-true pay or effort: " + ", ".join(f'"{w}"' for w in easy[:3]))
    if "whatsapp" in low and "hr" in low:
        score += 5
        flags.append("Recruitment only over WhatsApp.")
    new_domains = [r for r in whois_result.get("domains_checked", []) if r.get("is_under_6_months")]
    if new_domains:
        score += 25
    if re.search(r"[LU]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}", text):
        score -= 10
    score = max(0, min(100, score))
    verdict = "Likely Scam" if score >= 70 else "Suspicious" if score >= 40 else "Safe"
    reasons = dict(REASON_TEMPLATES[verdict])
    return {"risk_score": score, "verdict": verdict, "red_flags": flags, "reasons": reasons,
            "reason_hinglish": reasons["hinglish"], "reason_odia": reasons["or"]}


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
    prompt += (
        "{\n  \"risk_score\": number 0-100,\n  \"verdict\": \"Safe\"|\"Suspicious\"|\"Likely Scam\",\n"
        "  \"red_flags\": [\"exact suspicious quotes or red flag descriptions, in English\"],\n"
        "  \"reasons\": {\n"
        "    \"en\": \"2-3 simple sentences in English\",\n"
        "    \"hinglish\": \"same in Hinglish (Hindi in Latin script)\",\n"
        "    \"hi\": \"same in Hindi (Devanagari)\",\n"
        "    \"or\": \"same in Odia\",\n"
        "    \"bn\": \"same in Bengali\",\n"
        "    \"ta\": \"same in Tamil\",\n"
        "    \"te\": \"same in Telugu\",\n"
        "    \"mr\": \"same in Marathi\"\n  }\n}\n"
    )
    prompt += "Do not add any extra keys or commentary. Keep reasons short and simple."
    return prompt


def analyze_with_gemini(prompt: str):
    """Send prompt to Gemini and parse JSON. Returns None if Gemini is unavailable or fails."""
    if not client:
        return None
    try:
        response = client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
        resp_text = response.text or ""
        start = resp_text.find('{')
        end = resp_text.rfind('}') + 1
        if start != -1 and end > start:
            data = json.loads(resp_text[start:end])
            if data.get("verdict") not in ("Safe", "Suspicious", "Likely Scam"):
                data["verdict"] = "Suspicious"
            return data
    except Exception as e:
        print(f"Gemini call error: {e}")
    return None


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
    if gemini_result is None:
        gemini_result = heuristic_result(combined_text, checks, whois_result)

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

    # Per-language explanations; fill any language Gemini skipped from the verdict template
    template = REASON_TEMPLATES.get(verdict, REASON_TEMPLATES["Suspicious"])
    reasons = gemini_result.get('reasons') if isinstance(gemini_result.get('reasons'), dict) else {}
    reasons = {lang: (reasons.get(lang) or template[lang]) for lang in LANGUAGES}
    reason_hinglish = reasons["hinglish"]
    reason_odia = reasons["or"]

    return {
        'risk_score': risk_score,
        'verdict': verdict,
        'red_flags': combined_red_flags,
        'reason_hinglish': reason_hinglish,
        'reason_odia': reason_odia,
        'reasons': reasons,
        'mca_info': whois_result.get('mca_info'),
        'domain_reports': whois_result.get('domains_checked')
    }
