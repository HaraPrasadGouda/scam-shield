"""Identity-harvest offers: no fee, but an unsolicited 'shortlist', no interview and a government-ID
request before any offer letter. Runs the offline rules + ML (no Gemini) so results are deterministic.

The NEXORA text below is an AI-written example made to test the app. It is used ONLY as a regression
test here, never as training data or as evidence in the README."""
from backend.main import heuristic_result, run_local_checks


def check(text):
    return heuristic_result(text, run_local_checks(text), {})


def keys(text):
    return {h[0] for h in run_local_checks(text)["signals"]}


NEXORA_ID_HARVEST = """NEXORA DIGITAL SOLUTIONS
Talent Acquisition & Recruitment Team

Dear Candidate,

Congratulations! 🎉

Your profile has been shortlisted for the position of Junior Data Operations Associate (Remote) through our recruitment partner network.

Position Details:

- Employment Type: Full-time
- Work Mode: Remote
- Working Days: Monday–Friday
- Working Hours: 10 AM – 6 PM
- Monthly Compensation: ₹28,500 – ₹35,000
- Training Period: 7 days (Paid)

Job Responsibilities:

1. Verify and organize digital records.
2. Update product and customer information.
3. Prepare basic Excel reports.
4. Coordinate with the operations team.

Selection Process:

Your profile has been selected based on your academic background. No technical interview is required at this stage.

To complete the onboarding process, shortlisted candidates are requested to:

1. Complete the employee information form.
2. Submit a government-issued identity document for verification.
3. Attend a virtual orientation session.

Please note that the company follows a centralized onboarding procedure. All employment documentation will be shared after successful profile verification.

Application Reference: NDS/OPS/2026/10482

Response Deadline: 31 October 2026, 5:00 PM

Regards,
Talent Acquisition Team
Nexora Digital Solutions"""


def test_nexora_id_harvest_is_likely_scam():
    r = check(NEXORA_ID_HARVEST)
    assert r["verdict"] == "Likely Scam", r
    assert r["risk_score"] >= 70
    assert {"unsolicited_shortlist", "no_interview", "id_before_offer"} <= keys(NEXORA_ID_HARVEST)
    assert "identity" in r["reasons"]["en"].lower()


def test_greeting_alone_is_not_flagged():
    t = "Dear Candidate, we are hiring freshers for our Pune office. Apply through our careers page."
    assert not keys(t) & {"generic_greeting", "deadline_pressure", "no_verifiable_contact"}


def test_reply_date_in_real_offer_is_not_flagged():
    t = ("Dear Candidate, thank you for interviewing with us. We are pleased to offer you the Analyst role. "
         "Please confirm acceptance by 5 November. Offer letter is attached.")
    assert "deadline_pressure" not in keys(t)
    assert check(t)["verdict"] == "Safe"


def test_recruiter_outreach_stays_safe():
    t = ("Dear Candidate, we came across your profile on Naukri and it matches our Java Developer opening. "
         "Please share your updated resume at hr@acmesoft.in. Interview rounds start Monday.")
    assert check(t)["verdict"] == "Safe"


def test_id_after_offer_is_not_id_before_offer():
    t = ("Congratulations on accepting our offer! Please upload your PAN and Aadhaar on the onboarding portal "
         "https://onboard.acme.com before your joining date.")
    assert "id_before_offer" not in keys(t)


def test_safety_advice_is_not_an_id_request():
    t = "Never share your Aadhaar or bank details with anyone claiming to offer a job."
    assert "id_before_offer" not in keys(t)
