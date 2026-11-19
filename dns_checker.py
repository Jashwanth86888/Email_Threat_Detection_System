"""
dns_checker.py - DNS and Domain Verification Module for Computer Networks Project
==================================================================================
Key Computer Networks Concepts Demonstrated:
1. DNS (Domain Name System) Resolution: Translating human-readable domains to IP addresses.
2. MX (Mail Exchange) Records: Identifying which mail servers are designated to accept emails for a domain.
3. TXT Records (SPF & DMARC): Cryptographic and policy records published in DNS to prevent email spoofing.
4. Email-Only Domains: Recognizing RFC 5321 domains (e.g. hackerrankmail.com) that lack web A/AAAA records
   but have designated Mail Exchange (MX) and SPF records.

Author: Team 21 (Vasavi College of Engineering, CN 5th Sem)
Project: Email Threat Detection Platform (Rule-Based, Non-AI)
"""

import socket
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


def check_domain_dns(domain_name):
    """
    Performs comprehensive DNS queries to verify domain existence, MX records, and SPF/DMARC records.
    Properly handles dedicated email-sending domains that have MX/SPF records without HTTP website A-records.
    
    Parameters:
        domain_name (str): The domain to query (e.g., 'hackerrankmail.com' or 'google.com')
        
    Returns:
        dict: DNS inspection results including MX records, SPF record, DMARC record, and flags.
    """
    results = {
        "domain": domain_name,
        "domain_resolves": False,
        "ip_addresses": [],
        "has_mx": False,
        "mx_records": [],
        "has_spf": False,
        "spf_record": None,
        "has_dmarc": False,
        "dmarc_record": None,
        "dns_error": None
    }
    
    if not domain_name or "." not in domain_name:
        results["dns_error"] = "Invalid domain name syntax"
        return results

    # 1. Basic A/AAAA Record Lookup (for website IP addresses)
    has_a_record = False
    try:
        addr_info = socket.getaddrinfo(domain_name, None)
        ips = list(set([item[4][0] for item in addr_info]))
        results["ip_addresses"] = ips[:3]  # Keep first 3 IPs
        has_a_record = True
    except socket.gaierror:
        has_a_record = False
    except Exception as e:
        results["dns_error"] = str(e)

    # 2. MX and TXT Record Lookups using dnspython
    is_nxdomain = False
    if DNS_AVAILABLE:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0  # 3-second timeout for snappy response
        resolver.lifetime = 3.0

        # Query MX Records (Mail Exchange)
        try:
            mx_answers = resolver.resolve(domain_name, 'MX')
            mx_list = [f"{rdata.exchange.to_text().rstrip('.')} (pref: {rdata.preference})" for rdata in mx_answers]
            results["has_mx"] = len(mx_list) > 0
            results["mx_records"] = mx_list[:3]
        except dns.resolver.NXDOMAIN:
            is_nxdomain = True
            results["has_mx"] = False
        except (dns.resolver.NoAnswer, Exception):
            results["has_mx"] = False

        # Query SPF (TXT records on root domain)
        try:
            txt_answers = resolver.resolve(domain_name, 'TXT')
            for rdata in txt_answers:
                txt_str = b"".join(rdata.strings).decode('utf-8', errors='ignore')
                if txt_str.startswith("v=spf1"):
                    results["has_spf"] = True
                    results["spf_record"] = txt_str
                    break
        except Exception:
            pass

        # Query DMARC (TXT record on _dmarc.<domain>)
        try:
            dmarc_domain = f"_dmarc.{domain_name}"
            dmarc_answers = resolver.resolve(dmarc_domain, 'TXT')
            for rdata in dmarc_answers:
                txt_str = b"".join(rdata.strings).decode('utf-8', errors='ignore')
                if txt_str.startswith("v=DMARC1"):
                    results["has_dmarc"] = True
                    results["dmarc_record"] = txt_str
                    break
        except Exception:
            pass
    else:
        results["has_mx"] = has_a_record

    # In Computer Networks: An email domain exists if it has MX records, SPF/TXT records, OR A/AAAA records.
    # Dedicated email gateways (e.g. hackerrankmail.com) often omit web A records.
    if has_a_record or results["has_mx"] or results["has_spf"]:
        results["domain_resolves"] = True
        results["dns_error"] = None
    else:
        results["domain_resolves"] = False
        results["dns_error"] = f"Domain '{domain_name}' does not exist in DNS (NXDOMAIN) or has no mail/host records."

    return results
