import email
import re
from typing import Dict, Any, List

def extract_auth_results(auth_header: str | None) -> Dict[str, str]:
    """Extracts SPF, DKIM, and DMARC statuses from Authentication-Results header string."""
    if not auth_header:
        return {"spf": "none", "dkim": "none", "dmarc": "none"}
    
    results = {}
    for protocol in ["spf", "dkim", "dmarc"]:
        match = re.search(rf"{protocol}=(\w+)", auth_header, re.IGNORECASE)
        results[protocol] = match.group(1).lower() if match else "none"
    return results

def parse_eml_file(file_path: str) -> Dict[str, Any]:
    """Parses a raw .eml file and extracts headers and relay hops."""
    with open(file_path, "rb") as f:
        msg = email.message_from_binary_file(f)

    auth_header = msg.get("Authentication-Results")
    auth_status = extract_auth_results(auth_header)
    received_headers = msg.get_all("Received") or []

    return {
        "from": msg.get("From"),
        "to": msg.get("To"),
        "subject": msg.get("Subject"),
        "reply_to": msg.get("Reply-To"),
        "auth_results": auth_status,
        "received_chain": received_headers,
    }

def compute_final_threat_score(content_score: int, auth_results: Dict[str, str]) -> int:
    """Applies rule-based penalties for failing/softfailing security headers."""
    penalty = 0
    
    # SPF penalties
    if auth_results.get("spf") == "fail":
        penalty += 15
    elif auth_results.get("spf") == "softfail":
        penalty += 8
        
    # DKIM penalties
    if auth_results.get("dkim") == "fail":
        penalty += 15
        
    # DMARC penalties (strongest indicator of domain impersonation)
    if auth_results.get("dmarc") == "fail":
        penalty += 20

    return min(100, content_score + penalty)