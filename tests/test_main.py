from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

SAFE_OFFER = """Dear Candidate,

We are pleased to offer you an internship at Acme Corp (Official domain: hr@acme-corp.com).
Stipend: ₹8,000 per month.
Please reply to this email to schedule your joining formalities.

Regards,
HR
"""

SUSPICIOUS_OFFER = """Hello,

You have been selected. To confirm, please pay a registration fee of ₹1,500.
Send payment via UPI to 98765XXXXX.

Regards
"""

SCAM_OFFER = """Urgent! Limited seats. Pay a registration fee of ₹2,999 to confirm your seat via UPI.
Contact: +91-9xxxxxxxxx. Email: hiring.team@gmail.com
Send PAN and bank details immediately.
"""

REQUIRED_KEYS = {"risk_score", "verdict", "red_flags", "reason_hinglish", "reason_odia"}
ALLOWED_VERDICTS = {"Safe", "Suspicious", "Likely Scam"}


def _validate_response_json(data: dict):
    assert isinstance(data, dict), "response is not a JSON object"
    assert REQUIRED_KEYS.issubset(set(data.keys())), f"missing keys: {REQUIRED_KEYS - set(data.keys())}"

    # risk_score
    rs = data["risk_score"]
    assert isinstance(rs, (int, float)), "risk_score must be a number"
    assert 0 <= int(rs) <= 100, "risk_score out of range"

    # verdict
    assert data["verdict"] in ALLOWED_VERDICTS, f"unexpected verdict: {data['verdict']}"

    # red_flags
    assert isinstance(data["red_flags"], list), "red_flags must be a list"

    # reasons
    assert isinstance(data["reason_hinglish"], str), "reason_hinglish must be a string"
    assert isinstance(data["reason_odia"], str), "reason_odia must be a string"


def test_root_serves_html():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")


def test_safe_offer():
    resp = client.post("/check-offer", data={"offer_text": SAFE_OFFER})
    assert resp.status_code == 200
    data = resp.json()
    _validate_response_json(data)


def test_suspicious_offer_fee():
    resp = client.post("/check-offer", data={"offer_text": SUSPICIOUS_OFFER})
    assert resp.status_code == 200
    data = resp.json()
    _validate_response_json(data)


def test_scam_offer_gmail_urgent_payment():
    resp = client.post("/check-offer", data={"offer_text": SCAM_OFFER})
    assert resp.status_code == 200
    data = resp.json()
    _validate_response_json(data)
