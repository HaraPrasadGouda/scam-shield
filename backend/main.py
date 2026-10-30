from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Request
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


import contextvars
import datetime as _dt

# Per-visitor daily cap on Gemini checks (protects the shared free quota on a public deployment).
# GEMINI_PER_IP_DAILY=0 turns the cap off. Requests from localhost are never capped.
GEMINI_PER_IP_DAILY = int(os.getenv("GEMINI_PER_IP_DAILY", "3"))
_IP_USAGE: Dict[str, Any] = {}
_ALLOW_GEMINI = contextvars.ContextVar("allow_gemini", default=True)


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def take_gemini_slot(ip: str) -> bool:
    """True if this visitor may use Gemini for this check (and counts it)."""
    if GEMINI_PER_IP_DAILY <= 0 or ip in ("127.0.0.1", "::1", "localhost", "testclient"):
        return True
    today = _dt.date.today().isoformat()
    day, used = _IP_USAGE.get(ip, (today, 0))
    if day != today:
        used = 0
    if used >= GEMINI_PER_IP_DAILY:
        return False
    _IP_USAGE[ip] = (today, used + 1)
    return True


def gemini_available() -> bool:
    """False while Gemini is not configured, its quota is exhausted, or this visitor hit the daily cap."""
    import time
    return bool(client) and time.time() >= _GEMINI_PAUSED_UNTIL and _ALLOW_GEMINI.get()


def time_ok() -> bool:
    import time
    return time.time() >= _GEMINI_PAUSED_UNTIL


def note_gemini_error(e: Exception, where: str) -> None:
    """Log one short line; on quota errors pause Gemini calls until the retry time."""
    global _GEMINI_PAUSED_UNTIL
    import time
    msg = str(e)
    if "RESOURCE_EXHAUSTED" in msg or "429" in msg:
        m = re.search(r"retry in ([\d.]+)s", msg) or re.search(r"retryDelay['\"]?\s*:\s*['\"]([\d.]+)s", msg)
        wait = min(float(m.group(1)), 12 * 3600.0) if m else 3600.0
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


def _any_affirmed(patterns, low):
    """Like _any, but skips matches that are negated just before ("no registration fee", "never charge any fee")."""
    for p in patterns:
        for m in re.finditer(p, low):
            before = low[max(0, m.start() - 50):m.start()]
            if not re.search(r"\b(no|never|not|don'?t|do not|without|zero|free of|nahi|nahin|nhi|koi)\b[^.!\n]{0,40}$", before):
                return m.group(0)
    return None


AMT = r"(?:₹|rs\.?|inr)\s*\d[\d,]*"
AMT_WORDS = r"\b\d[\d,]{2,}\s*(?:rupees|rupaye|rupay|rupiya)\b"  # "1500 rupees", "2000 rupaye"

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
        # softer / other phrasings seen in real Indian job scams (sources in the README)
        r"(fee|fees|deposit|charges?)\s*(of|is|:|-)?\s*" + AMT_WORDS,
        AMT_WORDS + r".{0,25}(registration|deposit|fee|security|jama|voucher)",
        r"(pay|deposit|transfer|send)\s*" + AMT_WORDS,
        r"(activation|certificate|id card|background check|kyc)\s*(fee|fees|charges?|deposit)",
        r"(pay|paying)\s.{0,30}for\s+(the\s+|your\s+)?(internship\s+)?certificate",
        r"(buy|purchase)\s+(the\s+|a\s+|our\s+)?(starter\s+|training\s+|joining\s+|work\s+)?kit\b|\bkit\s+(worth|costs?|of|for)\s+" + AMT,
        r"(security|registration|fees?|deposit|charges?)\s+(amount\s+)?(jama|bharn\w*|deni|dena|dene)\b",
        r"(" + AMT + r"|" + AMT_WORDS + r")\s*(ka|ki|ke)?\s*(dene|dena|deni|bharne|bharna|jama|pay)\s*(honge|hoga|hogi|karne|karna|karo|kar)",
    ]),
    ("task_scam", 35, "Classic 'task' scam: paid per like/subscribe/review/click, commission, 'prepaid' or 'data tasks' with returns.", [
        r"like \d* ?(youtube|instagram)|youtube video|google (maps )?reviews?|5-star review",
        r"commission", r"brush the volume", r"data tasks?", r"\d+\s*-\s*\d+%\s*return|\d+% return",
        r"receptionist", r"prepaid task", r"withdraw anytime",
        r"like (and|&) subscribe|subscribe (to )?(our |the |these )?(youtube )?channels?|(follow|like) (instagram|insta|youtube) (accounts?|pages?|posts?|videos?)",
        r"(rate|review|rating)\s+(hotels?|movies?|products?|restaurants?|apps?)\s+(online|on google|and earn|to earn)|merchant task|recharge task|vip task|premium task",
        r"(send|share|upload)\s+(the\s+|us\s+)?screenshots?\s+.{0,40}(task|earn|paid|payment|commission)",
        r"(invest|pay|deposit)\s+" + AMT + r".{0,40}(get|receive|return)\w*\s+" + AMT,
    ]),
    ("upi_request", 65, "Asks you to approve a UPI 'request' or share PIN/OTP. Approving a request SENDS money from your account.", [
        r"request to approve", r"approve (it|the request)", r"collect request", r"upi pin", r"\botp\b",
        r"(phonepe|gpay|google pay|paytm) number",
    ]),
    ("personal_upi", 65, "Asks you to send money to a personal UPI ID / phone number. A real company never collects money from candidates, least of all into a personal UPI account.", [
        r"[\w.-]+@(ybl|okaxis|oksbi|okicici|okhdfcbank|paytm|apl|axl|ibl|upi|airtel|freecharge|jio)(?![\w.])",
        r"(send|pay|transfer)\w*\s.{0,40}(upi id|upi number|to (my|this|our) (upi|gpay|phonepe|paytm))",
    ]),
    ("govt_letter", 65, "Government appointment letter without any recruitment notification / advertisement number. Government jobs come only through official exams and notifications.", []),
    ("chat_only", 10, "Recruitment moves to WhatsApp/Telegram links instead of an official company channel.", [
        r"wa\.me/", r"t\.me/", r"telegram", r"on whats(app)?\b", r"whatsapp (group|number)",
    ]),
    ("chat_interview", 25, "The 'interview' happens only over Telegram or WhatsApp chat. Real companies interview on a call, video call or in person, and Naukri lists on-the-spot or chat/tele hiring as a scam sign.", [
        r"interviews?\s+(will\s+be\s+|is\s+|shall\s+be\s+)?(conducted|held|taken|done|scheduled)?\s*(on|via|through|over)\s+(telegram|whats\s?app\s+(chat|text|message)s?)",
        r"(telegram|whats\s?app\s+chat)\s+interview",
    ]),
    ("personal_email", 20, "HR uses a free Gmail/Yahoo/Outlook address instead of a company email.", [
        r"[\w.+-]+@(gmail|yahoo|outlook|hotmail|rediffmail)\.com\b",
    ]),
    ("unreal_pay", 15, "Too-good-to-be-true pay for very little work (per-day salary, guaranteed stipend, no experience).", [
        r"daily salary", r"(per day|/day|a day)\b.{0,20}" + AMT, AMT + r"\s*(per day|/day|a day|daily)",
        r"guaranteed stipend", r"no experience (needed|required)", r"\d+\s*-\s*\d+\s*minutes", r"only \d+ hours",
        r"earn\s+(up\s*to\s+)?(?:₹|rs\.?|inr)?\s*\d[\d,]*\s*(-|to)?\s*(?:₹|rs\.?|inr)?\s*\d*[\d,]*\s*(per day|daily|a day|/day|per hour|weekly)",
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

# ---- Identity-harvest pattern: no fee asked, but an unsolicited "shortlist" with no interview that wants your
# government ID before any offer letter. Each sign is weak alone (real offers also say "Dear Candidate" or give a
# reply date), so the weaker ones only count when they appear together with the stronger ones (see detect_signals).
ID_DOC = (r"(government[- ]issued|govt\.?[- ]issued|government|govt\.?)\s*(photo\s*)?(identity|id)\s*(document|proof|card)s?"
          r"|identity (document|proof)s?|\bid proofs?\b|photo id|aadhaa?r|\bpan (card|number|details)\b|passport"
          r"|bank (details|account)|cancell?ed cheque")
IDH_RULES = [
    ("unsolicited_shortlist", 10, "Says you were 'shortlisted' or 'selected' from your profile/academic background or a 'partner network', without you applying. Real companies select you after you apply and are interviewed.", [
        r"(profile|resume|cv)\s+(has|have)\s+been\s+(shortlisted|selected)\s+.{0,80}(through|via|from|by)\s+(our\s+)?(recruitment|hiring|placement|talent)?\s*(partner|network|database|portal|agency|agencies)",
        r"(selected|shortlisted)\s+(based on|on the basis of)\s+(your\s+)?(academic|educational|profile|resume|cv|qualification|background|marks)",
        r"recruitment partner network",
        r"(your\s+)?(profile|resume|cv)\s+(has|have)\s+been\s+(shortlisted|selected)",
        r"(we|our team)\s+(found|came across|got)\s+your\s+(profile|resume|cv)\s+(on|from|through)",
        r"(aapka|apka|tumhara)\s+(profile|resume|cv)\s+(select|shortlist)",
    ]),
    ("no_interview", 15, "Says no interview or test is needed. Real employers always interview or test before hiring.", [
        r"no\s+(technical\s+|formal\s+|personal\s+|hr\s+)?(interview|test|exam)s?\s+(is\s+|are\s+|will be\s+)?(required|needed|necessary|conducted)",
        r"without\s+(any\s+)?(interview|test|exam)",
        r"direct\s+(selection|joining|appointment)\s+without",
        r"interviews?\s+(is|are)\s+not\s+(required|needed|necessary)",
        r"no\s+(selection|screening)\s+(process|round)s?\s+(is\s+)?(required|needed)",
        r"(bina|koi)\s+interview\s*(ke|nahi|nahin|nhi)",
    ]),
    ("id_before_offer", 20, "Asks for your government ID / Aadhaar / PAN / bank details for 'verification' before giving any offer letter or contract. This is how identity-theft scams start: never share ID before a signed offer from a verified company.", []),
    ("no_verifiable_contact", 10, "No company website, company email, phone number, office address or CIN anywhere in the offer, only a team name. You cannot verify who is hiring.", []),
    ("generic_greeting", 5, "Generic greeting ('Dear Candidate') instead of your name, typical of mass scam messages.", [
        r"^\W*(dear|hello|hi)\s+(candidate|applicant|student|job seeker|aspirant|sir\s*/\s*madam)\b",
        r"\bdear\s+(candidate|applicant|job seeker|aspirant)\b",
    ]),
    ("deadline_pressure", 10, "Hard reply deadline to rush you before you can check the company.", [
        r"(response|reply|acceptance|confirmation)\s+deadline",
        r"(respond|reply|confirm|accept)\s+(to this\s+\w+\s+)?(by|before)\s+(\d{1,2}(st|nd|rd|th)?\s+\w+|today|tomorrow|tonight|\d{1,2}[:.]\d{2}|\d{1,2}\s*(am|pm))",
        r"today only|only today|aaj hi|within 24 hours|within 24 hrs",
    ]),
]
_IDH_PRE_OFFER = [
    r"(offer letter|appointment letter|employment (documentation|documents|contract)|contract|joining letter)s?\s+(will|shall)\s+be\s+(shared|issued|sent|provided|released|given)\s+(only\s+)?after",
    r"(documentation|documents|offer letter)\s+(will|shall)\s+be\s+(shared|issued|sent|provided)\s+after\s+(successful\s+)?(profile\s+|document\s+|kyc\s+|background\s+)?verification",
    r"(before|prior to)\s+(the\s+)?(offer letter|appointment letter|contract)",
    r"for\s+(profile\s+|kyc\s+|identity\s+|background\s+)?verification",
]
_IDH_REQUEST = r"(submit|send|share|upload|provide|forward|bhej\w*|de do)\b.{0,60}(" + ID_DOC + r")|(" + ID_DOC + r").{0,40}\b(submit|send|share|upload|provide|bhej\w*)"
_CONTACT = [
    r"https?://", r"www\.", r"\b[\w.+-]+@[\w-]+\.[\w.]+", r"\b[a-z0-9-]+\.(com|in|co\.in|org|net|io|ai|tech)\b",
    r"(\+?91[\s-]?)?\b[6-9]\d{4}[\s-]?\d{5}\b", r"\b0\d{2,4}[\s-]\d{6,8}\b", r"\b\d{3}[\s-]\d{3}[\s-]\d{4}\b",
    r"\b[1-9]\d{2}\s?\d{3}\b",  # PIN code
    r"\b(floor|road|street|nagar|sector|plot|tower|building|marg|lane|colony|phase)\b",
    r"[lu]\d{5}[a-z]{2}\d{4}[a-z]{3}\d{6}",
]


def detect_id_harvest(text: str, low: str, prior_keys: set) -> list:
    """Identity-harvest signals. Weak ones (no contact, generic greeting, deadline) count only next to strong ones."""
    hits = {}
    rules = {r[0]: r for r in IDH_RULES}
    for key in ("unsolicited_shortlist", "no_interview", "generic_greeting", "deadline_pressure"):
        k, w, f, pats = rules[key]
        ev = _any(pats, low)
        if ev:
            hits[key] = (k, w, f, ev)
    req = None
    for m in re.finditer(_IDH_REQUEST, low):
        if not re.search(r"\b(never|not|don'?t|do not|mat|kabhi)\b[^.\n]{0,30}$", low[max(0, m.start() - 40):m.start()] + low[m.start():m.start() + 12]):
            req = m
            break
    pre = _any(_IDH_PRE_OFFER, low)
    offer_given = re.search(r"offer letter\s+(is\s+)?(attached|enclosed)|(accepted|signed)\s+(our|the|your)\s+offer|thank you for (interviewing|attending)", low)
    if req and not offer_given and (pre or "no_interview" in hits or "unsolicited_shortlist" in hits):
        k, w, f, _ = rules["id_before_offer"]
        hits["id_before_offer"] = (k, w, f, req.group(0)[:80])
    if "no_interview" in hits and re.search(r"offer letter|appointment letter|joining letter|you (are|have been) (selected|hired)", low):
        k, w, f, ev = hits["no_interview"]
        hits["no_interview"] = (k, 25, "Says you are selected / will get an offer letter with no interview or test. Real employers always interview or test before hiring.", ev)
    strong = {"unsolicited_shortlist", "no_interview", "id_before_offer"} & set(hits)
    if not strong:
        return []  # deadline / greeting alone are normal in real offers
    if "deadline_pressure" in hits and "urgency" in prior_keys:
        del hits["deadline_pressure"]  # already counted as urgency
    # (short texts are already covered by the "no company name" check in heuristic_result)
    if len(strong) >= 2 and len(text) >= 600 and not _any(_CONTACT, low):
        k, w, f, _ = rules["no_verifiable_contact"]
        hits["no_verifiable_contact"] = (k, w, f, "no website / email / phone / address")
    order = [r[0] for r in IDH_RULES]
    return [hits[k] for k in order if k in hits]



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
        ev = _any_affirmed(patterns, low) if key == "money_ask" else _any(patterns, low)
        if ev:
            hits.append((key, weight, flag, ev))
    hits += detect_id_harvest(text, low, {h[0] for h in hits})
    return hits


# ---- ML layer: TF-IDF + Logistic Regression trained on 17,880 real job postings (EMSCAD, 866 fake) ----
_ML_MODEL = None
_ML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model", "scam_model.joblib")


def ml_scam_probability(text: str):
    """Probability (0-1) that the text looks like a known fake job post. None if the model is missing."""
    global _ML_MODEL
    try:
        if _ML_MODEL is None:
            if not os.path.exists(_ML_PATH):
                return None
            import joblib
            _ML_MODEL = joblib.load(_ML_PATH)
        return float(_ML_MODEL.predict_proba([text])[0][1])
    except Exception as e:
        print(f"ML model error: {str(e)[:120]}")
        return None


def ml_signal(prob):
    """(weight, flag) for the ML probability."""
    if prob is None or prob < 0.5:
        return 0, None
    pct = int(round(prob * 100))
    flag = f"Text matches patterns of known fake job posts (ML model trained on 17,880 real postings: {pct}% fake-like)."
    if prob >= 0.85:
        return 65, flag
    if prob >= 0.7:
        return 40, flag
    return 20, flag


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
        "ml_probability": ml_scam_probability(text),
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


# One place that turns a 0-100 score into the label shown everywhere (API, UI, Gemini or not).
LIKELY_SCAM_AT = 70
SUSPICIOUS_AT = 40


def verdict_for_score(score) -> str:
    score = int(score)
    if score >= LIKELY_SCAM_AT:
        return "Likely Scam"
    if score >= SUSPICIOUS_AT:
        return "Suspicious"
    return "Safe"


# Used instead of the generic "Likely Scam" text for 'task' scams (paid likes / reviews / prepaid tasks).
TASK_SCAM_REASONS = {
    "en": "This looks like a 'task' scam: they pay small amounts for likes, reviews or simple tasks, then ask you to pay for bigger 'prepaid' tasks and never return the money. Do not pay or deposit anything. Report it at cybercrime.gov.in or call 1930.",
    "hinglish": "Yeh 'task' scam lag raha hai: pehle like, review ya chhote task ke thode paise dete hain, phir bade 'prepaid' task ke liye paise jama karwate hain aur wapas nahi karte. Kuch bhi pay ya deposit mat karo. cybercrime.gov.in pe ya 1930 pe report karo.",
    "hi": "यह 'टास्क' वाला धोखा लग रहा है: पहले लाइक, रिव्यू या छोटे काम के थोड़े पैसे देते हैं, फिर बड़े 'प्रीपेड' टास्क के लिए पैसे जमा करवाते हैं और वापस नहीं करते। कुछ भी भुगतान या जमा न करें। cybercrime.gov.in पर या 1930 पर कॉल करके शिकायत करें।",
    "or": "ଏହା 'ଟାସ୍କ' ଠକେଇ ଭଳି ଲାଗୁଛି: ପ୍ରଥମେ ଲାଇକ, ରିଭ୍ୟୁ କିମ୍ବା ଛୋଟ କାମ ପାଇଁ ଅଳ୍ପ ଟଙ୍କା ଦିଅନ୍ତି, ତା'ପରେ ବଡ଼ 'ପ୍ରିପେଡ' ଟାସ୍କ ପାଇଁ ଟଙ୍କା ଜମା କରାନ୍ତି ଏବଂ ଫେରାନ୍ତି ନାହିଁ। କିଛି ବି ଟଙ୍କା ଦିଅନ୍ତୁ ନାହିଁ କି ଜମା କରନ୍ତୁ ନାହିଁ। cybercrime.gov.in ରେ କିମ୍ବା 1930 ରେ ରିପୋର୍ଟ କରନ୍ତୁ।",
    "bn": "এটি 'টাস্ক' প্রতারণা বলে মনে হচ্ছে: প্রথমে লাইক, রিভিউ বা ছোট কাজের জন্য অল্প টাকা দেয়, তারপর বড় 'প্রিপেইড' টাস্কের জন্য টাকা জমা করায় এবং আর ফেরত দেয় না। কোনো টাকা দেবেন না বা জমা করবেন না। cybercrime.gov.in-এ বা 1930 নম্বরে অভিযোগ করুন।",
    "ta": "இது 'டாஸ்க்' மோசடியாகத் தெரிகிறது: முதலில் லைக், ரிவ்யூ அல்லது சிறிய வேலைகளுக்குச் சிறிது பணம் தருவார்கள், பிறகு பெரிய 'ப்ரீபெய்ட்' டாஸ்க்குகளுக்குப் பணம் கட்டச் சொல்லி திருப்பித் தர மாட்டார்கள். எந்தப் பணமும் செலுத்தவோ டெபாசிட் செய்யவோ வேண்டாம். cybercrime.gov.in அல்லது 1930 இல் புகார் செய்யவும்.",
    "te": "ఇది 'టాస్క్' మోసంలా కనిపిస్తోంది: మొదట లైక్‌లు, రివ్యూలు లేదా చిన్న పనులకు కొంచెం డబ్బు ఇస్తారు, తర్వాత పెద్ద 'ప్రీపెయిడ్' టాస్క్‌ల కోసం డబ్బు కట్టించి తిరిగి ఇవ్వరు. ఏమీ చెల్లించవద్దు, డిపాజిట్ చేయవద్దు. cybercrime.gov.in లో లేదా 1930 కి కాల్ చేసి ఫిర్యాదు చేయండి.",
    "mr": "ही 'टास्क' फसवणूक वाटते: आधी लाइक, रिव्ह्यू किंवा छोट्या कामांसाठी थोडे पैसे देतात, नंतर मोठ्या 'प्रीपेड' टास्कसाठी पैसे भरायला लावतात आणि परत करत नाहीत. काहीही पैसे भरू नका किंवा जमा करू नका. cybercrime.gov.in वर किंवा 1930 वर तक्रार करा."
}


# Used instead of the generic "Likely Scam" text when the risk is ID theft rather than a fee.
ID_HARVEST_REASONS = {
    "en": "This looks like an identity-theft scam: you were 'selected' without a proper application or interview, and they want your government ID before any offer letter. Do not send Aadhaar, PAN, passport or bank details. Verify the company on MCA and its official website, and report it at cybercrime.gov.in or call 1930.",
    "hinglish": "Yeh identity chori wala scam lag raha hai: bina proper apply ya interview ke 'select' kar liya, aur offer letter se pehle government ID maang rahe hain. Aadhaar, PAN, passport ya bank details mat bhejo. Company ko MCA aur official website pe check karo, aur cybercrime.gov.in pe ya 1930 pe report karo.",
    "hi": "यह पहचान चोरी वाला धोखा लग रहा है: बिना सही आवेदन या इंटरव्यू के 'चयन' कर लिया गया, और ऑफ़र लेटर से पहले सरकारी पहचान पत्र माँगा जा रहा है। आधार, पैन, पासपोर्ट या बैंक विवरण न भेजें। कंपनी को MCA और आधिकारिक वेबसाइट पर जाँचें, और cybercrime.gov.in पर या 1930 पर कॉल करके शिकायत करें।",
    "or": "ଏହା ପରିଚୟ ଚୋରି ଠକେଇ ଭଳି ଲାଗୁଛି: ଠିକ୍ ଆବେଦନ କିମ୍ବା ଇଣ୍ଟରଭ୍ୟୁ ବିନା 'ଚୟନ' କରାଯାଇଛି, ଏବଂ ଅଫର ଲେଟର ପୂର୍ବରୁ ସରକାରୀ ପରିଚୟ ପତ୍ର ମାଗୁଛନ୍ତି। ଆଧାର, PAN, ପାସପୋର୍ଟ କିମ୍ବା ବ୍ୟାଙ୍କ ବିବରଣୀ ପଠାନ୍ତୁ ନାହିଁ। କମ୍ପାନୀକୁ MCA ଓ ଅଫିସିଆଲ ୱେବସାଇଟରେ ଯାଞ୍ଚ କରନ୍ତୁ, ଏବଂ cybercrime.gov.in ରେ କିମ୍ବା 1930 ରେ ରିପୋର୍ଟ କରନ୍ତୁ।",
    "bn": "এটি পরিচয় চুরির প্রতারণা বলে মনে হচ্ছে: সঠিক আবেদন বা ইন্টারভিউ ছাড়াই 'নির্বাচিত' করা হয়েছে, আর অফার লেটারের আগেই সরকারি পরিচয়পত্র চাওয়া হচ্ছে। আধার, প্যান, পাসপোর্ট বা ব্যাংকের তথ্য পাঠাবেন না। কোম্পানিকে MCA ও অফিসিয়াল ওয়েবসাইটে যাচাই করুন, এবং cybercrime.gov.in-এ বা 1930 নম্বরে অভিযোগ করুন।",
    "ta": "இது அடையாளத் திருட்டு மோசடியாகத் தெரிகிறது: முறையான விண்ணப்பம் அல்லது நேர்காணல் இல்லாமல் 'தேர்வு' செய்யப்பட்டதாகச் சொல்கிறார்கள், வேலை வாய்ப்புக் கடிதத்துக்கு முன்பே அரசு அடையாள ஆவணம் கேட்கிறார்கள். ஆதார், பான், பாஸ்போர்ட் அல்லது வங்கி விவரங்களை அனுப்ப வேண்டாம். நிறுவனத்தை MCA மற்றும் அதிகாரப்பூர்வ இணையதளத்தில் சரிபார்க்கவும், cybercrime.gov.in அல்லது 1930 இல் புகார் செய்யவும்.",
    "te": "ఇది గుర్తింపు దొంగతనం మోసంలా కనిపిస్తోంది: సరైన దరఖాస్తు లేదా ఇంటర్వ్యూ లేకుండానే 'ఎంపిక' చేశామంటున్నారు, ఆఫర్ లెటర్ కంటే ముందే ప్రభుత్వ గుర్తింపు పత్రం అడుగుతున్నారు. ఆధార్, పాన్, పాస్‌పోర్ట్ లేదా బ్యాంక్ వివరాలు పంపవద్దు. కంపెనీని MCA మరియు అధికారిక వెబ్‌సైట్‌లో తనిఖీ చేయండి, cybercrime.gov.in లో లేదా 1930 కి కాల్ చేసి ఫిర్యాదు చేయండి.",
    "mr": "ही ओळख चोरीची फसवणूक वाटते: योग्य अर्ज किंवा मुलाखतीशिवाय 'निवड' झाल्याचे सांगितले जात आहे, आणि ऑफर लेटरपूर्वीच सरकारी ओळखपत्र मागितले जात आहे. आधार, पॅन, पासपोर्ट किंवा बँक तपशील पाठवू नका. कंपनीची MCA आणि अधिकृत वेबसाइटवर खात्री करा, आणि cybercrime.gov.in वर किंवा 1930 वर तक्रार करा."
}


def heuristic_result(text: str, checks: dict, whois_result: dict) -> dict:
    """Rule-based score used when Gemini is unavailable or fails."""
    hits = checks.get("signals") or detect_signals(text)
    score = 5 + sum(h[1] for h in hits)
    flags = [f"{h[2]} (found: \"{h[3]}\")" for h in hits]
    ml_w, ml_flag = ml_signal(checks.get("ml_probability"))
    if ml_flag:
        score += ml_w
        flags.append(ml_flag)
    if any(r.get("is_under_6_months") for r in whois_result.get("domains_checked", [])):
        score += 25
        flags.append("Website/email domain was registered less than 6 months ago.")
    company = (whois_result.get("mca_info") or {}).get("company_name", "")
    has_contact = re.search(r"https?://|www\.|@[\w-]+\.", text.lower())
    if (not company or company.startswith("Not ")) and not has_contact and len(text) < 600:
        # A missing employer is a strong red flag only together with another warning sign;
        # on its own (e.g. a short genuine SMS) it just adds a little caution.
        score += 35 if hits else 15
        flags.append("No company name, website or official email anywhere in the message. Verify who is actually hiring.")
    if re.search(r"[LU]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}", text):
        score -= 10
    score = max(0, min(100, score))
    verdict = verdict_for_score(score)
    reasons = dict(REASON_TEMPLATES[verdict])
    keys = {h[0] for h in hits}
    if verdict == "Likely Scam" and "id_before_offer" in keys and not keys & {"money_ask", "upi_request", "personal_upi"}:
        reasons = dict(ID_HARVEST_REASONS)
    elif verdict == "Likely Scam" and "task_scam" in keys:
        reasons = dict(TASK_SCAM_REASONS)
    return {"risk_score": score, "verdict": verdict, "red_flags": flags, "reasons": reasons,
            "reason_hinglish": reasons["hinglish"], "reason_odia": reasons["or"]}


# Rule hits that are strong enough on their own that a lenient Gemini answer must not hide them.
HARD_FLAGS = {"money_ask", "upi_request", "personal_upi", "govt_letter", "task_scam", "id_before_offer"}


def combine_results(rules: dict, gemini: Optional[dict], rule_keys: set) -> dict:
    """Final score, label, red flags and reasons.

    Without Gemini this is exactly the rules + ML result. With Gemini, Gemini's score is used, except that
    when the rules found a hard red flag (fee / UPI / task / ID before offer / fake govt letter) or already
    say Likely Scam, the final score never goes below the rules score (Gemini can raise it, not water it down).
    The label is always derived from the final score with verdict_for_score().
    """
    if not gemini:
        return dict(rules)
    try:
        g_score = int(round(float(gemini.get("risk_score", 50))))
    except (TypeError, ValueError):
        g_score = 50
    g_score = max(0, min(100, g_score))
    strong = rules["verdict"] == "Likely Scam" or bool(set(rule_keys) & HARD_FLAGS)
    score = max(g_score, rules["risk_score"]) if strong else g_score
    verdict = verdict_for_score(score)

    g_flags = [str(f) for f in (gemini.get("red_flags") or []) if f] if isinstance(gemini.get("red_flags"), list) else []
    flags = list(dict.fromkeys((rules["red_flags"] if strong else []) + g_flags))

    g_reasons = gemini.get("reasons") if isinstance(gemini.get("reasons"), dict) else {}
    fallback = rules["reasons"] if rules["verdict"] == verdict else REASON_TEMPLATES[verdict]
    if g_reasons and verdict_for_score(g_score) == verdict:
        reasons = {lang: (g_reasons.get(lang) or fallback[lang]) for lang in LANGUAGES}
    else:
        reasons = {lang: fallback[lang] for lang in LANGUAGES}  # Gemini's words were written for another label
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
    if checks.get('ml_probability') is not None:
        prompt += f"- ml_fake_job_probability (TF-IDF model trained on 17,880 real job posts; strong signal above 0.7): {checks['ml_probability']:.2f}\n"
    
    suspicious = checks.get('suspicious_lines', [])
    whois_flags = whois_result.get('red_flags', [])
    all_suspicious = suspicious + whois_flags
    
    if all_suspicious:
        prompt += "- suspicious_lines or domain red flags:\n"
        for s in all_suspicious:
            prompt += f"  - {s}\n"

    prompt += (f"- rule_based_risk_score: {checks.get('rule_score')} (this app labels 0-{SUSPICIOUS_AT - 1} Safe, "
               f"{SUSPICIOUS_AT}-{LIKELY_SCAM_AT - 1} Suspicious, {LIKELY_SCAM_AT}-100 Likely Scam)\n") if checks.get('rule_score') is not None else ""
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
async def check_offer(request: Request, offer_text: Optional[str] = Form(None), file: Optional[UploadFile] = File(None)):
    if not offer_text and not file:
        raise HTTPException(status_code=400, detail="Provide offer text or upload a file")
    if client and time_ok():
        _ALLOW_GEMINI.set(take_gemini_slot(client_ip(request)))

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

    # Rules + ML score (always computed; it is also the floor when hard red flags fire)
    rules_result = heuristic_result(combined_text, checks, whois_result)
    checks["rule_score"] = rules_result["risk_score"]

    # Compose prompt and call Gemini (optional)
    prompt = compose_gemini_prompt(combined_text, checks, whois_result)
    gemini_result = analyze_with_gemini(prompt)
    final = combine_results(rules_result, gemini_result, {h[0] for h in checks.get("signals", [])})

    risk_score = final["risk_score"]
    verdict = verdict_for_score(risk_score)

    # Merge unique red flags with the WHOIS ones
    combined_red_flags = list(dict.fromkeys(final["red_flags"] + whois_result.get('red_flags', [])))
    if not combined_red_flags and risk_score > 30:
        combined_red_flags = checks.get('suspicious_lines') or ["Potential scam indicators detected in text format."]

    reasons = final["reasons"]
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
