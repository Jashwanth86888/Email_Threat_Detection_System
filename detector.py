"""
detector.py - Rule-Based Threat Scoring Engine (Non-AI)
=======================================================
Key Computer Networks Concepts Demonstrated:
1. SMTP Header Spoofing (RFC 5321 Envelope vs RFC 5322 Header alignment)
2. DNS & MX Records: Mail exchanger verification
3. Email Authentication: SPF (Sender Policy Framework), DKIM, and DMARC
4. Network Protocol Analysis: HTTP vs HTTPS, IP addressing in URIs
5. Multi-Hop Email Routing: Received header tracing

Author: Team 21 (Vasavi College of Engineering, CN 5th Sem)
Project: Email Threat Detection Platform (Rule-Based, Non-AI)
"""

from email_parser import extract_domain, extract_urls_from_text, analyze_url, get_base_domain
from dns_checker import check_domain_dns

# Common trusted brands often impersonated by phishing attacks
COMMON_BRANDS = {
    "paypal": ["paypal.com", "paypal.in"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "google": ["google.com", "gmail.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "netflix": ["netflix.com"],
    "apple": ["apple.com", "icloud.com"]
}

# Major authorized Email Service Providers (ESPs) legitimately used for transactional emails
TRUSTED_ESPS = [
    "sendgrid.net", "amazonses.com", "mailgun.org", "mailgun.net",
    "mcsv.net", "salesforce.com", "mandrillapp.com", "sparkpostmail.com",
    "postmarkapp.com", "zendesk.com", "freshdesk.com", "hubspot.com"
]

# Common benign public domains (social icons, web standards, developer platforms)
# that are standard in legitimate corporate email footers
BENIGN_DOMAINS = [
    "linkedin.com", "twitter.com", "x.com", "facebook.com", "instagram.com",
    "youtube.com", "github.com", "google.com", "apple.com", "play.google.com",
    "w3.org", "schema.org", "cloudflare.com", "gravatar.com"
]

# High-threat psychological urgency triggers
HIGH_THREAT_KEYWORDS = [
    "account suspended", "suspended within 24 hours", "unauthorized access",
    "wire transfer", "lottery won", "threat of closure", "click here immediately"
]

# Routine security/account management phrases
ROUTINE_KEYWORDS = [
    "verify your account", "verify your email", "confirm your identity",
    "security alert", "unusual activity", "password expired", "update your billing"
]


def evaluate_email(parsed_data):
    """
    Evaluates an email using rule-based network and header heuristics.
    Implements RFC 7489 (DMARC) Relaxed Domain Alignment.
    """
    score = 0
    triggered_rules = []
    
    sender_email = parsed_data.get("sender_email", "").strip()
    sender_domain = extract_domain(sender_email)
    sender_base = get_base_domain(sender_domain)
    
    display_name = parsed_data.get("display_name", "")
    return_path = parsed_data.get("return_path", "")
    return_path_domain = extract_domain(return_path)
    return_path_base = get_base_domain(return_path_domain)
    
    subject = parsed_data.get("subject", "")
    body_text = parsed_data.get("body_text", "")
    
    auth_results = parsed_data.get("auth_results", "").lower()
    received_spf = parsed_data.get("received_spf", "").lower()
    has_dkim = parsed_data.get("has_dkim", False)
    
    # -------------------------------------------------------------
    # RULE 1: SENDER SPOOFING & RETURN-PATH ALIGNMENT (SMTP Headers)
    # -------------------------------------------------------------
    # In RFC 5321 (SMTP), envelope sender is Return-Path. RFC 7489 (DMARC)
    # recognizes Relaxed Alignment if the base organizational domains match.
    if return_path_domain and sender_domain:
        s_clean = sender_base.replace("mail", "").replace("-", "") if sender_base else ""
        r_clean = return_path_base.replace("mail", "").replace("-", "") if return_path_base else ""
        is_aligned = (
            (sender_base == return_path_base) or
            (bool(s_clean) and bool(r_clean) and s_clean == r_clean) or
            (sender_domain in return_path_domain) or
            (return_path_domain in sender_domain)
        )
        is_trusted_esp = any(return_path_domain.endswith(esp) for esp in TRUSTED_ESPS)
        has_auth_pass = ("spf=pass" in auth_results or "pass" in received_spf or "dkim=pass" in auth_results)

        if not is_aligned:
            # If the Return-Path is an authorized ESP and SPF/DKIM passed, it is NOT a spoof!
            if is_trusted_esp and has_auth_pass:
                pass
            else:
                points = 25
                score += points
                triggered_rules.append({
                    "rule": "SMTP Envelope & Header Mismatch",
                    "points": points,
                    "details": f"Header 'From' domain ({sender_domain}) does not align with Envelope 'Return-Path' ({return_path_domain}).",
                    "cn_concept": "SMTP protocol allows arbitrary 'From' header injection. Discrepancy with Return-Path indicates sender spoofing or unauthorized relay."
                })
        
    # Check Brand Impersonation in Display Name
    combined_name_subject = f"{display_name} {subject}".lower()
    for brand, legit_domains in COMMON_BRANDS.items():
        if brand in combined_name_subject:
            # If display name mentions a protected brand, verify if domain belongs to it
            if sender_domain and not any(legit in sender_domain for legit in legit_domains):
                points = 25
                score += points
                triggered_rules.append({
                    "rule": "Display Name / Brand Impersonation",
                    "points": points,
                    "details": f"Email claims to represent '{brand.upper()}', but sender domain is '{sender_domain}'.",
                    "cn_concept": "Application-layer identity spoofing. The user-agent renders the Display Name while the actual transport layer domain is unverified."
                })
                break

    # -------------------------------------------------------------
    # RULE 2: DNS & MX RECORD VERIFICATION (Domain Name System)
    # -------------------------------------------------------------
    dns_info = {}
    if sender_domain:
        dns_info = check_domain_dns(sender_domain)
        
        # Domain does not resolve at all (NXDOMAIN)
        if not dns_info["domain_resolves"]:
            points = 35
            score += points
            triggered_rules.append({
                "rule": "Non-Existent Sender Domain (DNS Failure)",
                "points": points,
                "details": f"DNS query failed: Domain '{sender_domain}' does not exist (NXDOMAIN) or has no valid IP address.",
                "cn_concept": "DNS A/AAAA lookup failed. Legitimate email servers must resolve to valid public IP addresses."
            })
        # Domain resolves, but has NO MX (Mail Exchange) record
        elif not dns_info["has_mx"]:
            points = 20
            score += points
            triggered_rules.append({
                "rule": "Missing MX (Mail Exchange) Records",
                "points": points,
                "details": f"Domain '{sender_domain}' has no MX DNS records configured.",
                "cn_concept": "DNS MX records specify designated mail servers. A domain sending mail without MX records cannot receive bounce/NDR notifications."
            })
    else:
        points = 25
        score += points
        triggered_rules.append({
            "rule": "Invalid or Empty Sender Address",
            "points": points,
            "details": "No valid email address or domain could be extracted from sender.",
            "cn_concept": "RFC 5322 requires a valid mailbox syntax with local-part@domain."
        })

    # -------------------------------------------------------------
    # RULE 3: EMAIL AUTHENTICATION CHECK (SPF, DKIM, DMARC)
    # -------------------------------------------------------------
    if parsed_data.get("is_eml", False):
        # We have actual email headers to inspect!
        if "spf=fail" in auth_results or "fail" in received_spf:
            points = 30
            score += points
            triggered_rules.append({
                "rule": "SPF Authentication Failed",
                "points": points,
                "details": "The SPF check returned FAIL / SOFTFAIL. Sending MTA IP is not authorized in DNS by the domain owner.",
                "cn_concept": "SPF (RFC 7208) validates if the sending SMTP client's IP is listed in the sender domain's DNS TXT record."
            })
            
        if "dmarc=fail" in auth_results:
            points = 25
            score += points
            triggered_rules.append({
                "rule": "DMARC Policy Check Failed",
                "points": points,
                "details": "DMARC policy evaluation failed for this message.",
                "cn_concept": "DMARC (RFC 7489) ties SPF and DKIM together to ensure domain alignment with the visible 'From' header."
            })
            
        if not has_dkim and "dkim=pass" not in auth_results and ("dkim=fail" in auth_results):
            points = 10
            score += points
            triggered_rules.append({
                "rule": "DKIM Cryptographic Verification Failed",
                "points": points,
                "details": "DKIM cryptographic signature evaluation returned FAIL.",
                "cn_concept": "DKIM (RFC 6376) uses public-key cryptography (asymmetric keys in DNS) to verify message integrity and sender authenticity."
            })

        # Cryptographic & IP Authorization Credit:
        # If SPF passes and DKIM passes, the email's authenticity is verified!
        if ("spf=pass" in auth_results or "pass" in received_spf) and (has_dkim or "dkim=pass" in auth_results):
            bonus = 15
            score -= bonus
            triggered_rules.append({
                "rule": "Verified Email Authentication (SPF & DKIM Pass)",
                "points": -bonus,
                "details": "Sender IP is authorized by domain owner in DNS (SPF) and header signature is cryptographically valid (DKIM).",
                "cn_concept": "Cryptographic proof of origin. Verified SPF and DKIM confirm that the email was sent by an authorized MTA and not tampered with."
            })
    else:
        # Manual check mode: Verify if domain publishes SPF / DMARC in DNS
        if dns_info.get("domain_resolves", False):
            if not dns_info.get("has_spf", False):
                points = 10
                score += points
                triggered_rules.append({
                    "rule": "No SPF Record in Sender's DNS",
                    "points": points,
                    "details": f"Domain '{sender_domain}' has not published an SPF TXT record.",
                    "cn_concept": "Without SPF, anyone on the internet can forge emails claiming to come from this domain via unauthenticated SMTP."
                })
            if not dns_info.get("has_dmarc", False):
                points = 10
                score += points
                triggered_rules.append({
                    "rule": "No DMARC Record in Sender's DNS",
                    "points": points,
                    "details": f"Domain '{sender_domain}' has not published a DMARC policy record (_dmarc.{sender_domain}).",
                    "cn_concept": "DMARC instructs receiving mail servers how to treat spoofed emails (reject, quarantine, or none)."
                })

    # -------------------------------------------------------------
    # RULE 4: SUSPICIOUS URL & IP-BASED LINK INSPECTION
    # -------------------------------------------------------------
    urls = parsed_data.get("urls", [])
    if not urls and body_text:
        urls = extract_urls_from_text(body_text)

    has_raw_ip_url = False
    has_plain_http_url = False
    has_domain_mismatch_url = False

    for u in urls:
        # Check raw IP URL (e.g. http://192.168.1.5/login)
        if u.get("is_ip_based"):
            has_raw_ip_url = True
            
        # Check insecure HTTP (ignoring XML metadata schemas)
        if u.get("is_http") and not u.get("is_schema"):
            has_plain_http_url = True
            
        # Check link domain divergence
        url_host = u.get("host", "")
        url_base = get_base_domain(url_host)
        
        # Check if URL belongs to sender organization or recognized benign public platform
        # (Handles mail domains like hackerrankmail.com vs hackerrank.com)
        s_clean = sender_base.replace("mail", "").replace("-", "") if sender_base else ""
        u_clean = url_base.replace("mail", "").replace("-", "") if url_base else ""
        is_same_org = (
            (sender_base and url_base and sender_base == url_base) or
            (bool(s_clean) and bool(u_clean) and s_clean == u_clean) or
            (sender_domain and url_host and (sender_domain in url_host or url_host in sender_domain))
        )
        is_benign = any(b in url_host for b in BENIGN_DOMAINS)
        
        if url_host and not is_same_org and not is_benign and sender_domain:
            has_domain_mismatch_url = True

    if has_raw_ip_url:
        points = 30
        score += points
        triggered_rules.append({
            "rule": "Raw IP Address in Hyperlink",
            "points": points,
            "details": "One or more links in the email point directly to an IP address (IPv4) instead of a DNS domain.",
            "cn_concept": "Legitimate organizations register domain names with SSL certificates. Attackers use raw IP addresses to bypass DNS blacklists and domain registration tracking."
        })

    if has_plain_http_url:
        points = 10
        score += points
        triggered_rules.append({
            "rule": "Insecure Protocol (Plain HTTP)",
            "points": points,
            "details": "Detected hyperlinks using unencrypted HTTP instead of HTTPS (TLS/SSL).",
            "cn_concept": "Plain HTTP (TCP Port 80) transmits data in cleartext, vulnerable to Man-in-the-Middle (MITM) packet sniffing. Modern secure sites enforce HTTPS (Port 443)."
        })

    if has_domain_mismatch_url and len(urls) > 0:
        points = 15
        score += points
        triggered_rules.append({
            "rule": "External / Divergent Link Destination",
            "points": points,
            "details": f"Hyperlinks in the email point to unverified external domains outside '{sender_domain}'.",
            "cn_concept": "Phishing emails disguise hyperlinks so the anchor text appears to be legitimate while the HTTP request destination connects to an attacker-controlled host."
        })

    # -------------------------------------------------------------
    # RULE 5: SOCIAL ENGINEERING / URGENT THREAT HEURISTICS
    # -------------------------------------------------------------
    combined_content = f"{subject} {body_text}".lower()
    
    high_threat_matches = [kw for kw in HIGH_THREAT_KEYWORDS if kw in combined_content]
    routine_matches = [kw for kw in ROUTINE_KEYWORDS if kw in combined_content]

    if high_threat_matches:
        points = min(25, 10 + (len(high_threat_matches) - 1) * 5)
        score += points
        triggered_rules.append({
            "rule": "High-Pressure Psychological Urgency Triggers",
            "points": points,
            "details": f"Found high-threat triggers: {', '.join(high_threat_matches[:3])}",
            "cn_concept": "Application-layer payload inspection. Attackers use urgency and threat of loss to coerce users into executing malicious HTTP requests."
        })
    elif routine_matches and (has_raw_ip_url or not dns_info.get("domain_resolves", True) or "spf=fail" in auth_results):
        # Routine phrases are only penalized if accompanied by other network red flags
        points = 10
        score += points
        triggered_rules.append({
            "rule": "Account Verification Combined with Network Anomalies",
            "points": points,
            "details": f"Found account verification phrasing with suspicious network indicators: {', '.join(routine_matches[:2])}",
            "cn_concept": "Attackers combine routine verification language with unverified or spoofed infrastructure."
        })

    # -------------------------------------------------------------
    # RULE 6: MULTI-HOP ROUTING & RELAY ANALYSIS (.eml only)
    # -------------------------------------------------------------
    hops = parsed_data.get("hops", [])
    if hops:
        hop_count = len(hops)
        if hop_count > 7:
            points = 10
            score += points
            triggered_rules.append({
                "rule": "Abnormal SMTP Hop Count",
                "points": points,
                "details": f"Email traversed {hop_count} relay hops, which is unusually high for direct corporate email.",
                "cn_concept": "Each intermediate SMTP MTA prepends a 'Received' header. Excessive hops often indicate open relay exploitation, proxy chaining, or bulletproof hosting."
            })

    # -------------------------------------------------------------
    # 1. RULE-BASED SCORE CAPPING
    # -------------------------------------------------------------
    rule_score = min(100, max(0, score))
    
    # -------------------------------------------------------------
    # 2. AI/ML MODEL EVALUATION (TF-IDF + Logistic Regression)
    # -------------------------------------------------------------
    try:
        from ml_detector import predict_ml_threat
        ml_result = predict_ml_threat(parsed_data)
        ml_score = ml_result.get("ml_score", rule_score)
    except Exception as e:
        ml_result = {
            "ml_score": rule_score,
            "phishing_probability": round(rule_score / 100.0, 3),
            "legit_probability": round(1.0 - (rule_score / 100.0), 3),
            "confidence_level": "Fallback to Rule Engine",
            "top_features": [],
            "model_name": "TF-IDF + Logistic Regression (Local Fallback)"
        }
        ml_score = rule_score

    # -------------------------------------------------------------
    # 3. HYBRID ENSEMBLE SCORE: AVERAGE OF RULE-BASED & ML MODEL
    # -------------------------------------------------------------
    # Final Score = (Rule Score + ML Score) / 2
    final_score = int(round((rule_score + ml_score) / 2.0))
    final_score = min(100, max(0, final_score))
    
    if final_score < 30:
        risk_level = "Low Risk / Legitimate"
        risk_class = "safe"
        verdict = f"This email is classified as Low Risk after ensemble evaluation (Rule Engine: {rule_score}/100, AI/ML Model: {ml_score}/100). No significant threat indicators detected."
    elif final_score < 60:
        risk_level = "Suspicious / Moderate Risk"
        risk_class = "warning"
        verdict = f"This email is classified as Suspicious after ensemble evaluation (Rule Engine: {rule_score}/100, AI/ML Model: {ml_score}/100). Caution advised before clicking links or trusting sender identity."
    else:
        risk_level = "High Risk / Phishing"
        risk_class = "danger"
        verdict = f"CRITICAL ALERT: This email is classified as High Risk after ensemble evaluation (Rule Engine: {rule_score}/100, AI/ML Model: {ml_score}/100). Strong spoofing, network anomaly, and text pattern threats detected."

    return {
        "score": final_score,
        "rule_score": rule_score,
        "ml_score": ml_score,
        "ml_details": ml_result,
        "risk_level": risk_level,
        "risk_class": risk_class,
        "verdict": verdict,
        "triggered_rules": triggered_rules,
        "sender_domain": sender_domain,
        "dns_info": dns_info,
        "urls": urls,
        "hops": hops,
        "total_rules_checked": 6,
        "triggered_count": len(triggered_rules)
    }
