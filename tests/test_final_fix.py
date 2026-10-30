"""Final fix pass: one score -> label function, Gemini cannot water down hard red flags, and extra rules for
common Indian job-scam patterns (task scams, soft 'refundable' fees, certificate fees, personal UPI, chat-only
interviews).

All offer strings below are SHORT HAND-WRITTEN TEST CASES written for these tests, modelled on the patterns
described in the advisories cited in the README. They are test inputs only, never training data or README evidence.
Gemini is always mocked here, so no API key or quota is used.
"""
import pytest
from fastapi.testclient import TestClient

import backend.main as M

client = TestClient(M.app)

NO_WHOIS = {"red_flags": [], "domains_checked": [], "mca_info": None}


def rules(text):
    return M.heuristic_result(text, M.run_local_checks(text), {})


def keys(text):
    return {h[0] for h in M.run_local_checks(text)["signals"]}


# ---------- 1. one label function ----------
@pytest.mark.parametrize("score,label", [(0, "Safe"), (39, "Safe"), (40, "Suspicious"), (69, "Suspicious"),
                                         (70, "Likely Scam"), (72, "Likely Scam"), (100, "Likely Scam")])
def test_verdict_for_score(score, label):
    assert M.verdict_for_score(score) == label


# hand-written test case
FEE_SCAM = ("Congratulations! You are selected for the Data Entry internship. Pay a refundable registration fee "
            "of Rs 1,999 to confirm your seat within 24 hours. Contact hr.desk.jobs@gmail.com")
# hand-written test case
SAFE_OFFER = ("Hi Priya, thank you for interviewing with Acme Analytics Pvt Ltd last week. Please find your offer "
              "letter attached. Stipend: Rs 15,000 per month. Reply to careers@acme-analytics.in with any questions. "
              "Office: 4th Floor, Prestige Tower, MG Road, Bengaluru 560001.")

LENIENT = {"risk_score": 20, "verdict": "Safe", "red_flags": ["Looks like a normal internship"],
           "reasons": {"en": "Looks fine.", "hinglish": "Theek lag raha hai."}}
STRICT = {"risk_score": 85, "verdict": "Suspicious", "red_flags": ["Gemini: unusual wording"],
          "reasons": {"en": "Be careful.", "hinglish": "Dhyan rakho."}}
MISLABELLED_72 = {"risk_score": 72, "verdict": "Suspicious", "red_flags": ["x"], "reasons": {}}


# ---------- 2. combining rules + Gemini (mocked) ----------
def test_without_gemini_result_is_rules_result():
    r = rules(FEE_SCAM)
    assert M.combine_results(r, None, keys(FEE_SCAM)) == r


def test_lenient_gemini_cannot_water_down_hard_flags():
    r = rules(FEE_SCAM)
    assert r["verdict"] == "Likely Scam" and "money_ask" in keys(FEE_SCAM)
    out = M.combine_results(r, LENIENT, keys(FEE_SCAM))
    assert out["risk_score"] >= r["risk_score"]
    assert out["verdict"] == "Likely Scam"
    assert any("pay money" in f for f in out["red_flags"])          # rule evidence is shown
    assert out["reasons"]["en"] != "Looks fine."                     # Gemini's 'Safe' words not shown under 'Likely Scam'


def test_strict_gemini_can_raise_and_label_follows_score():
    r = rules(SAFE_OFFER)
    assert r["verdict"] == "Safe"
    out = M.combine_results(r, STRICT, keys(SAFE_OFFER))
    assert out["risk_score"] == 85 and out["verdict"] == "Likely Scam"   # Gemini said 'Suspicious' but 85 is Likely Scam


def test_gemini_may_lower_when_no_hard_flag():
    r = rules(SAFE_OFFER)
    out = M.combine_results(r, {"risk_score": 3, "verdict": "Safe", "red_flags": [], "reasons": {}}, keys(SAFE_OFFER))
    assert out["risk_score"] == 3 and out["verdict"] == "Safe"


def test_72_is_never_labelled_suspicious():
    out = M.combine_results(rules(SAFE_OFFER), MISLABELLED_72, keys(SAFE_OFFER))
    assert out["risk_score"] == 72 and out["verdict"] == "Likely Scam"
    assert set(out["reasons"]) == set(M.LANGUAGES)


@pytest.mark.parametrize("gem,text,want", [(LENIENT, FEE_SCAM, "Likely Scam"), (STRICT, SAFE_OFFER, "Likely Scam"),
                                           (MISLABELLED_72, SAFE_OFFER, "Likely Scam"), (None, SAFE_OFFER, "Safe")])
def test_api_label_always_matches_score(monkeypatch, gem, text, want):
    monkeypatch.setattr(M, "analyze_with_gemini", lambda prompt: dict(gem) if gem else None)
    monkeypatch.setattr(M, "run_whois_and_mca_checks", lambda t: NO_WHOIS)
    d = client.post("/check-offer", data={"offer_text": text}).json()
    assert d["verdict"] == M.verdict_for_score(d["risk_score"]) == want
    assert set(d["reasons"]) == set(M.LANGUAGES)


# ---------- 3. new rules (hand-written test cases) ----------
SCAMS = {
    "task_like_subscribe": ("Part time job from home. Just like and subscribe YouTube channels and send screenshots. "
                            "Earn Rs 3000 daily. Join t.me/dailytasks", "task_scam"),
    "refundable_amount": ("You are selected as Data Entry Operator. Kindly transfer a refundable amount of Rs 2,500 for "
                          "laptop dispatch.", "money_ask"),
    "one_time_onboarding": ("Internship confirmed. A one-time onboarding charge of ₹1,499 applies before joining.", "money_ask"),
    "starter_kit": ("Selected candidates must buy the starter kit worth Rs 1999 before training starts.", "money_ask"),
    "certificate_fee_rupees": ("Internship is free, only a certificate fee of 299 rupees is paid at the end.", "money_ask"),
    "certificate_fee_hinglish": ("Internship bilkul free hai, bas certificate ke liye 499 rupees dene honge.", "money_ask"),
    "security_hinglish": ("Aapka selection ho gaya hai. Joining ke liye 2000 rupaye security jama karne honge.", "money_ask"),
    "personal_upi": ("To confirm your seat send the amount to UPI ID rahul.hr24@ybl and share the screenshot.", "personal_upi"),
}


@pytest.mark.parametrize("name", sorted(SCAMS))
def test_new_scam_patterns_are_likely_scam(name):
    text, key = SCAMS[name]
    assert key in keys(text)
    assert rules(text)["verdict"] == "Likely Scam"


def test_task_scam_gets_task_explanation_in_all_languages():
    r = rules(SCAMS["task_like_subscribe"][0])
    assert r["reasons"] == M.TASK_SCAM_REASONS and set(r["reasons"]) == set(M.LANGUAGES)


def test_chat_only_interview_is_a_warning_not_a_verdict_by_itself():
    text = ("Thank you for applying to Acme Analytics Pvt Ltd (www.acme-analytics.in). Your interview will be conducted "
            "on Telegram chat with our HR team on Monday.")
    assert "chat_interview" in keys(text)
    assert rules(text)["verdict"] in ("Safe", "Suspicious")


def test_negated_fee_is_not_a_money_ask():
    text = ("Walk-in interview for Java developers at Acme Analytics Pvt Ltd, 3rd Floor, MG Road, Bengaluru. "
            "There is no registration fee or interview fee. Bring your resume.")
    assert "money_ask" not in keys(text)
    assert rules(text)["verdict"] == "Safe"


def test_negation_does_not_hide_a_real_fee_later():
    text = "No registration fee! Only a refundable security deposit of Rs 2000 for the laptop, pay on joining day."
    assert "money_ask" in keys(text)


def test_genuine_offer_stays_safe():
    assert rules(SAFE_OFFER)["verdict"] == "Safe"
