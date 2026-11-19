"""
email_parser.py - Email & Network Header Extraction Module
===========================================================
Key Computer Networks Concepts Demonstrated:
1. RFC 5322 / RFC 822 Email Message Format: Parsing headers and MIME body parts.
2. SMTP Envelope vs Header: Differentiating 'From' (displayed header) and 'Return-Path' (envelope sender).
3. SMTP Relay Hops ('Received' headers): Tracking the chain of Mail Transfer Agents (MTAs) and IP hops.
4. URI/URL Inspection: Extracting application layer hyperlinks, checking IPv4 vs Domain targets.

Author: Team 21 (Vasavi College of Engineering, CN 5th Sem)
Project: Email Threat Detection Platform (Rule-Based, Non-AI)
"""

import re
import ipaddress
from urllib.parse import urlparse
import email
from email import policy
from email.utils import parseaddr


# Regular expression to extract URLs from text and HTML bodies
URL_REGEX = re.compile(
    r'(https?://[^\s<>"\')]+)',
    re.IGNORECASE
)

# Regex to detect IP addresses embedded in URLs (IPv4)
IPV4_REGEX = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?$')


def extract_domain(email_address):
    """
    Extracts the domain portion of an email address.
    Example: 'support@paypal.com' -> 'paypal.com'
    """
    if not email_address or '@' not in email_address:
        return ""
    # Strip angle brackets if present: <user@domain.com>
    cleaned = email_address.strip("<> ").strip()
    parts = cleaned.split('@')
    return parts[-1].lower() if len(parts) > 1 else ""


def get_base_domain(domain):
    """
    Extracts the organizational base domain (e.g. 'em.hackerrank.com' -> 'hackerrank.com',
    'bounces.google.com' -> 'google.com', 'support.sbi.co.in' -> 'sbi.co.in').
    Implements RFC 7489 (DMARC) Relaxed Domain Alignment.
    """
    if not domain:
        return ""
    cleaned = domain.strip("<> .").lower()
    parts = cleaned.split('.')
    # Handle two-part TLDs like .co.in, .com.au, .co.uk, .gov.in, .org.in
    if len(parts) >= 3 and parts[-2] in ["co", "com", "gov", "org", "edu", "net", "ac"] and len(parts[-1]) <= 3:
        return '.'.join(parts[-3:])
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return cleaned


def analyze_url(url_string):
    """
    Analyzes an individual URL for Computer Networks indicators:
    - Protocol / Scheme (HTTP vs HTTPS)
    - Hostname / Domain
    - Whether the host is a raw IP address (RFC 791 IPv4) instead of a DNS hostname
    - Port number (standard 80/443 vs unusual high ports)
    """
    try:
        parsed = urlparse(url_string)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        
        # Strip port if present for host evaluation
        host = netloc.split(':')[0] if ':' in netloc else netloc
        
        # XML schema namespaces (e.g. xmlns=http://www.w3.org/1999/xhtml, http://schema.org)
        # are structural HTML metadata, not clickable insecure HTTP links
        is_schema = any(s in url_string.lower() for s in ["schema.org", "w3.org/1999", "w3.org/2000"])
        
        is_ip = False
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False
            
        return {
            "original_url": url_string,
            "scheme": scheme,
            "host": host,
            "is_http": (scheme == "http" and not is_schema),
            "is_schema": is_schema,
            "is_ip_based": is_ip,
            "is_suspicious_port": (parsed.port not in [None, 80, 443]) if parsed.port else False
        }
    except Exception:
        return {
            "original_url": url_string,
            "scheme": "unknown",
            "host": "unknown",
            "is_http": False,
            "is_schema": False,
            "is_ip_based": False,
            "is_suspicious_port": False
        }


def extract_urls_from_text(text):
    """
    Finds all unique URLs from a text/body string and analyzes them.
    """
    if not text:
        return []
    raw_urls = URL_REGEX.findall(text)
    # Deduplicate while preserving order
    seen = set()
    analyzed_urls = []
    for u in raw_urls:
        clean_u = u.rstrip(".,;!\"')")
        if clean_u not in seen:
            seen.add(clean_u)
            analyzed_urls.append(analyze_url(clean_u))
    return analyzed_urls


def parse_received_headers(received_headers_list):
    """
    Computer Networks Concept:
    Every SMTP Mail Transfer Agent (MTA) prepends a 'Received:' header line to the email.
    Reading these bottom-to-top traces the email's physical journey across the Internet.
    
    Example header line:
    'from mail.evil-server.net (unknown [185.220.101.5]) by mx.google.com with ESMTPS...'
    """
    hops = []
    # Regex to find IP addresses inside square brackets [x.x.x.x] common in Received headers
    ip_finder = re.compile(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]')
    
    for idx, header_val in enumerate(received_headers_list, start=1):
        found_ips = ip_finder.findall(header_val)
        hops.append({
            "hop_number": idx,
            "raw_header": header_val.strip(),
            "extracted_ips": found_ips
        })
    return hops


def parse_eml_file_bytes(file_bytes):
    """
    Parses a complete RFC 5322 .eml file byte-stream into structured metadata.
    """
    msg = email.message_from_bytes(file_bytes, policy=policy.default)
    
    # 1. Basic Headers
    subject = msg.get("Subject", "")
    from_raw = msg.get("From", "")
    display_name, sender_email = parseaddr(from_raw)
    return_path = msg.get("Return-Path", "").strip("<> ")
    message_id = msg.get("Message-ID", "")
    date_header = msg.get("Date", "")
    
    # 2. Authentication Headers (SPF, DKIM, DMARC)
    auth_results = msg.get("Authentication-Results", "")
    received_spf = msg.get("Received-SPF", "")
    dkim_signature = msg.get("DKIM-Signature", "")
    
    # 3. SMTP Hop headers
    received_list = msg.get_all("Received", [])
    hops = parse_received_headers(received_list)
    
    # 4. Extract Body (Plain text and HTML)
    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition'))
            if ctype in ['text/plain', 'text/html'] and 'attachment' not in cdispo:
                payload = part.get_payload(decode=True)
                if payload:
                    body_text += payload.decode('utf-8', errors='ignore') + "\n"
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body_text = payload.decode('utf-8', errors='ignore')

    # 5. Extract and analyze all URLs in the email body
    extracted_urls = extract_urls_from_text(body_text)

    return {
        "is_eml": True,
        "sender_email": sender_email if sender_email else from_raw,
        "display_name": display_name,
        "return_path": return_path,
        "subject": subject,
        "date": date_header,
        "message_id": message_id,
        "body_text": body_text,
        "urls": extracted_urls,
        "hops": hops,
        "auth_results": auth_results,
        "received_spf": received_spf,
        "has_dkim": bool(dkim_signature)
    }
