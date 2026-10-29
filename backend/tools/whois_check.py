import re
import datetime
import whois
from typing import Dict, List, Any

# Common public email providers to ignore for domain WHOIS checks
PUBLIC_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", 
    "rediffmail.com", "icloud.com", "aol.com", "live.com"
}

MCA_SEARCH_URL = "https://www.mca.gov.in/content/mca/global/en/data-and-reports/company-master-data/company-master-data.html"

def extract_domains(text: str) -> List[str]:
    """Extract domains from URLs and corporate email addresses in the text."""
    domains = set()
    
    # URL domains
    url_matches = re.findall(r'https?://(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text, re.IGNORECASE)
    for d in url_matches:
        domains.add(d.lower())

    # Email domains
    email_matches = re.findall(r'[\w.+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text, re.IGNORECASE)
    for d in email_matches:
        d_lower = d.lower()
        if d_lower not in PUBLIC_EMAIL_DOMAINS:
            domains.add(d_lower)

    return list(domains)

def check_domain_age(domain: str) -> Dict[str, Any]:
    """Check domain creation date using python-whois. Flag if under 6 months old (180 days)."""
    result = {
        "domain": domain,
        "creation_date": None,
        "age_days": None,
        "is_under_6_months": False,
        "error": None
    }
    try:
        w = whois.whois(domain)
        cdate = w.creation_date
        if isinstance(cdate, list):
            cdate = cdate[0]
        
        if cdate:
            if isinstance(cdate, datetime.datetime):
                result["creation_date"] = cdate.isoformat()
                delta = datetime.datetime.now() - cdate
                age_days = delta.days
                result["age_days"] = age_days
                if age_days < 180:
                    result["is_under_6_months"] = True
    except Exception as e:
        result["error"] = str(e)
    
    return result

def extract_company_info(text: str) -> Dict[str, Any]:
    """Extract company name or CIN references from text and provide MCA verification link."""
    cin_pattern = r'[L|U]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}'
    cin_match = re.search(cin_pattern, text)
    cin = cin_match.group(0) if cin_match else None

    # Try to find a company name: "<Name> Pvt Ltd / Private Limited / Limited / LLP / Inc ..."
    company_name = None
    suffix = r"(?:Private Limited|Pvt\.? Ltd\.?|Limited|Ltd\.?|LLP|Inc\.?|Technologies|Solutions|Services|Corp(?:oration)?)"
    m = re.search(r"((?:[A-Z][A-Za-z0-9&.\-]*[ \t]){1,4}?" + suffix + r")\b", text)
    if m:
        company_name = m.group(1).strip(" .,")
    else:
        for p in [r"\bAbout (?:us:?\s*)?([A-Z][A-Za-z0-9&]+)",
                  r"\bTeam ([A-Z][A-Za-z0-9&]+)",
                  r"\b(?:calling|writing) from ([A-Z][A-Za-z0-9&]+)",
                  r"\b(?:Internship|Program|position|role|Intern) at ([A-Z][A-Za-z0-9&]+(?:\s[A-Z][A-Za-z0-9&]+){0,2})"]:
            m = re.search(p, text)
            if m and m.group(1).lower() not in {"the", "our", "us", "you", "your", "team", "teams"}:
                company_name = m.group(1).strip(" .,")
                break

    return {
        "company_name": company_name or "Not explicitly specified",
        "cin": cin,
        "mca_verify_link": MCA_SEARCH_URL
    }

def run_whois_and_mca_checks(text: str) -> Dict[str, Any]:
    """Run WHOIS domain age checks and MCA verification prep."""
    domains = extract_domains(text)
    domain_reports = []
    red_flags = []

    for d in domains:
        report = check_domain_age(d)
        domain_reports.append(report)
        if report.get("is_under_6_months"):
            age = report.get("age_days", "unknown")
            red_flags.append(f"Domain '{d}' was registered recently (under 6 months old / ~{age} days old - high scam risk)")
        # A failed WHOIS lookup (network/timeout) is not evidence of a scam, so it is not flagged.

    mca_info = extract_company_info(text)

    return {
        "domains_checked": domain_reports,
        "red_flags": red_flags,
        "mca_info": mca_info
    }
