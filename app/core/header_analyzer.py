import re
import email
from email.policy import default

def extract_email_address(header_val: str) -> str:
    """Extract clean email address from header string like 'John Doe <john@example.com>'."""
    if not header_val:
        return ""
    match = re.search(r'<([^>]+)>', header_val)
    if match:
        return match.group(1).strip().lower()
    # Check if header is just an email address
    if "@" in header_val:
        return header_val.strip().lower()
    return ""

def extract_domain(email_addr: str) -> str:
    """Extract domain part of an email address."""
    if "@" in email_addr:
        return email_addr.split("@")[-1].strip().lower()
    return ""

class EmailHeaderAnalyzer:
    """Parser and risk analyzer for email headers and MIME headers."""

    @classmethod
    def analyze_headers(cls, raw_headers_str: str) -> dict:
        """Parse raw RFC822/EML header text and evaluate security posture."""
        risk_score = 0.0
        flags = []
        details = {}

        if not raw_headers_str or not raw_headers_str.strip():
            return {"score": 0.0, "flags": [], "details": {}}

        try:
            msg = email.message_from_string(raw_headers_str, policy=default)
        except Exception as e:
            return {
                "score": 30.0,
                "flags": [f"Malformed or invalid header format: {str(e)}"],
                "details": {}
            }

        from_hdr = msg.get("From", "")
        return_path = msg.get("Return-Path", "")
        reply_to = msg.get("Reply-To", "")
        auth_results = msg.get("Authentication-Results", "")
        received_spf = msg.get("Received-SPF", "")
        subject = msg.get("Subject", "")

        from_addr = extract_email_address(from_hdr)
        from_domain = extract_domain(from_addr)
        
        return_addr = extract_email_address(return_path)
        return_domain = extract_domain(return_addr)

        reply_addr = extract_email_address(reply_to)
        reply_domain = extract_domain(reply_addr)

        details["from"] = from_hdr
        details["from_address"] = from_addr
        details["return_path"] = return_path
        details["reply_to"] = reply_to
        details["subject"] = subject

        # 1. Check Display Name Spoofing (Brand name in display name vs generic domain)
        display_name = from_hdr.split("<")[0].strip('"\' ') if "<" in from_hdr else ""
        if display_name:
            # Check if display name claims to be a brand like PayPal, Google, Bank but email domain is free/unrelated
            brand_in_display = any(b in display_name.lower() for b in ["paypal", "google", "microsoft", "apple", "bank", "chase", "support", "helpdesk", "security"])
            if brand_in_display and from_domain not in ["paypal.com", "google.com", "microsoft.com", "apple.com", "chase.com"]:
                risk_score += 35.0
                flags.append(f"Display Name Spoofing detected: Display name '{display_name}' claims brand status, but actual domain is '{from_domain}'.")

        # 2. Check From vs Return-Path domain mismatch
        if from_domain and return_domain and from_domain != return_domain:
            risk_score += 30.0
            flags.append(f"Domain mismatch between From header ('{from_domain}') and Return-Path ('{return_domain}').")

        # 3. Check From vs Reply-To domain mismatch
        if from_domain and reply_domain and from_domain != reply_domain:
            risk_score += 25.0
            flags.append(f"Domain mismatch between From header ('{from_domain}') and Reply-To header ('{reply_domain}').")

        # 4. Check SPF authentication results
        combined_auth = (auth_results + " " + received_spf).lower()
        if "spf=fail" in combined_auth or "spf=softfail" in combined_auth:
            risk_score += 30.0
            flags.append("SPF Authentication failed or softfailed for sender host.")
        elif "spf=none" in combined_auth:
            risk_score += 10.0
            flags.append("No SPF authentication record found.")

        # 5. Check DKIM authentication results
        if "dkim=fail" in combined_auth:
            risk_score += 30.0
            flags.append("DKIM digital signature verification failed.")
        
        # 6. Check DMARC authentication results
        if "dmarc=fail" in combined_auth:
            risk_score += 35.0
            flags.append("DMARC alignment evaluation failed.")

        score = min(100.0, risk_score)
        
        return {
            "score": round(score, 1),
            "flags": flags,
            "details": details
        }
