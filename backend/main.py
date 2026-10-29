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
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

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


@app.get("/health")
async def health():
    return {"status": "ok", "gemini": bool(client), "model": GEMINI_MODEL}


@app.get("/")
async def serve_index():
    """Serve frontend/index.html at root '/'."""
    frontend_path = os.path.join(os.path.dirname(__file__), "../frontend/index.html")
    if os.path.exists(frontend_path):
        return FileResponse(frontend_path)
    return HTMLResponse("<h1>Scam Shield API is running. frontend/index.html not found.</h1>", status_code=200)


_GEMINI_PAUSED_UNTIL = 0.0


def gemini_available() -> bool:
    """False while Gemini is not configured or its quota is exhausted (skip the slow failing call)."""
    import time
    return bool(client) and time.time() >= _GEMINI_PAUSED_UNTIL


def note_gemini_error(e: Exception, where: str) -> None:
    """Log one short line; on quota errors pause Gemini calls until the retry time."""
    global _GEMINI_PAUSED_UNTIL
    import time
    msg = str(e)
    if "RESOURCE_EXHAUSTED" in msg or "429" in msg:
        m = re.search(r"retry in ([\d.]+)s", msg)
        wait = float(m.group(1)) if m else 3600.0
        _GEMINI_PAUSED_UNTIL = time.time() + wait
        print(f"Gemini quota exhausted ({where}); using offline rules/OCR for the next {int(wait // 60)} min")
    else:
        print(f"Gemini error ({where}): {msg[:200]}")


_OCR = None


def offline_ocr(content: bytes) -> str:
    """Read text from an image without any API key (RapidOCR, runs on CPU)."""
    global _OCR
    try:
        if _OCR is None:
            from rapidocr_onnxruntime import RapidOCR
            _OCR = RapidOCR()
        result, _ = _OCR(content)
        if not result:
            return ""
        # sort boxes top-to-bottom, left-to-right, and join lines
        result.sort(key=lambda r: (round(r[0][0][1] / 15), r[0][0][0]))
        return "\n".join(r[1] for r in result)
    except Exception as e:
        print(f"Offline OCR error: {e}")
        return ""


async def extract_text_from_file(file: UploadFile) -> str:
    """Extract text from an uploaded file using pypdf for PDFs and Gemini OCR for images."""
    content = await file.read()
    content_type = file.content_type or ""

    # Plain text files (.txt / .eml)
    if content_type.startswith("text/") or file.filename.lower().endswith(('.txt', '.eml')):
        return content.decode("utf-8", errors="ignore").strip()

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

    # Image extraction: Gemini OCR if available, else offline OCR (RapidOCR)
    if content_type.startswith("image/") or file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.webp')):
        if not gemini_available():
            return offline_ocr(content)
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
            text = (response.text or "").strip()
            return text or offline_ocr(content)
        except Exception as e:
            note_gemini_error(e, "OCR")
            return offline_ocr(content)

    return ""


def _any(patterns, low):
    """Return the first matched snippet for any regex in patterns, else None."""
    for p in patterns:
        m = re.search(p, low)
        if m:
            return m.group(0)
    return None


AMT = r"(?:₹|rs\.?|inr)\s*\d[\d,]*"

# Each rule: (key, weight, human-readable red flag, regex patterns). Weights add up into the risk score.
RULES = [
    ("money_ask", 65, "Asks you to pay money to get the job (fee / deposit / paid plan). Real employers never charge candidates.", [
        r"(registration|enrol?ment|training|security|joining|processing|onboarding|verification|refundable|kit|uniform|laptop)\s*(security\s*)?(fee|fees|charges?|deposit|amount|money)",
        r"(fee|fees|deposit|charges?)\s*(of|is|:|-)?\s*" + AMT,
        AMT + r"\s*(registration|deposit|fee|enrol)",
        r"(complete|pay)\s*(the|your)?\s*" + AMT,
        r"(deposit|pay)\s*" + AMT,
        r"internship (plans?|program) below|choos\w* one of the .{0,40}plans",
        r"(after|on) (the )?payment",
    ]),
    ("task_scam", 35, "Classic 'task' scam: paid per like/review/click, commission, or 'data tasks' with returns.", [
        r"like \d* ?(youtube|instagram)|youtube video|google (maps )?reviews?|5-star review",
        r"commission", r"brush the volume", r"data tasks?", r"\d+\s*-\s*\d+%\s*return|\d+% return",
        r"receptionist", r"prepaid task", r"withdraw anytime",
    ]),
    ("upi_request", 65, "Asks you to approve a UPI 'request' or share PIN/OTP. Approving a request SENDS money from your account.", [
        r"request to approve", r"approve (it|the request)", r"collect request", r"upi pin", r"\botp\b",
        r"(phonepe|gpay|google pay|paytm) number",
    ]),
    ("govt_letter", 65, "Government appointment letter without any recruitment notification / advertisement number. Government jobs come only through official exams and notifications.", []),
    ("chat_only", 10, "Recruitment moves to WhatsApp/Telegram links instead of an official company channel.", [
        r"wa\.me/", r"t\.me/", r"telegram", r"on whats(app)?\b", r"whatsapp (group|number)",
    ]),
    ("personal_email", 20, "HR uses a free Gmail/Yahoo/Outlook address instead of a company email.", [
        r"[\w.+-]+@(gmail|yahoo|outlook|hotmail|rediffmail)\.com\b",
    ]),
    ("unreal_pay", 15, "Too-good-to-be-true pay for very little work (per-day salary, guaranteed stipend, no experience).", [
        r"daily salary", r"(per day|/day|a day)\b.{0,20}" + AMT, AMT + r"\s*(per day|/day|a day|daily)",
        r"guaranteed stipend", r"no experience (needed|required)", r"\d+\s*-\s*\d+\s*minutes", r"only \d+ hours",
    ]),
    ("urgency", 15, "Pressure tactics to stop you from checking (limited seats, closing today, immediate).", [
        r"within \d+ (hours?|hrs)", r"limited (seats|places|slots)", r"closing today", r"\bhurry\b", r"last chance",
        r"immediately", r"immediate joining", r"interview:? tomorrow", r"otherwise the offer will be cancell?ed",
        r"confirm your seat",
    ]),
    ("referral", 15, "Referral cashback / bring-your-friends rewards: a pyramid-style money model, not a job.", [
        r"referral (cashback|bonus|reward)", r"for every (student|friend|person) you bring",
    ]),
    ("documents", 10, "Asks for Aadhaar / PAN / bank details before any verified offer.", [
        r"aadhaa?r", r"\bpan (card|number|details)\b", r"bank (details|account number)",
    ]),
]


def detect_signals(text: str) -> list:
    """Run every rule on the text. Returns a list of (key, weight, flag, evidence)."""
    low = re.sub(r"\s+", " ", text.lower())  # PDFs break lines mid-sentence
    hits = []
    for key, weight, flag, patterns in RULES:
        if key == "govt_letter":
            if re.search(r"government of india|ministry of|govt\. of india", low) and \
               re.search(r"appointment letter|hereby appointed|appointed to the post", low) and \
               not re.search(r"(advertisement|advt|notification|employment notice)\s*(no|number)", low):
                hits.append((key, weight, flag, "appointment letter"))
            continue
        ev = _any(patterns, low)
        if ev:
            hits.append((key, weight, flag, ev))
    return hits


def run_local_checks(text: str) -> dict:
    """Rule-based checks, also passed to Gemini as evidence."""
    hits = detect_signals(text)
    keys = {h[0] for h in hits}
    return {
        "personal_email": "personal_email" in keys,
        "fee_keywords": "money_ask" in keys,
        "missing_cin": not re.search(r"[LU]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}", text),
        "suspicious_lines": [f"{h[2]} (found: \"{h[3]}\")" for h in hits],
        "signals": hits,
    }




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
    hits = checks.get("signals") or detect_signals(text)
    score = 5 + sum(h[1] for h in hits)
    flags = [f"{h[2]} (found: \"{h[3]}\")" for h in hits]
    if any(r.get("is_under_6_months") for r in whois_result.get("domains_checked", [])):
        score += 25
        flags.append("Website/email domain was registered less than 6 months ago.")
    company = (whois_result.get("mca_info") or {}).get("company_name", "")
    has_contact = re.search(r"https?://|www\.|@[\w-]+\.", text.lower())
    if (not company or company.startswith("Not ")) and not has_contact and len(text) < 600:
        score += 35
        flags.append("No company name, website or official email anywhere in the message. Verify who is actually hiring.")
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
    if not gemini_available():
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
        note_gemini_error(e, "analysis")
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
        elif not offer_text:
            raise HTTPException(status_code=422, detail="Could not read any text from this file. Try a clearer image/PDF, or paste the text instead.")

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
